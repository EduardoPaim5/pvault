from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from typing import Sequence

from pty_harness import (
    PtyProcess,
    SplitPtyProcess,
    add_record,
    initialize_vault,
    invocation_contains_secret,
    isolated_environment,
    pid_exists,
    process_signal_ignored,
    process_state,
    wait_until,
)


REPOSITORY = Path(__file__).resolve().parents[2]
BUILD_DIRECTORY = Path(
    os.environ.get("PVAULT_BUILD_DIR", str(REPOSITORY / "build" / "debug"))
).resolve()
PVAULT = BUILD_DIRECTORY / "pvault"
ROFI_TEST_PVAULT = Path(os.environ.get("PVAULT_TEST_ROFI_PVAULT", ""))
SIGNAL_LAUNCHER = Path(os.environ.get("PVAULT_TEST_SIGNAL_LAUNCHER", ""))


class CliPtyIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not PVAULT.is_file():
            raise unittest.SkipTest(f"build the CLI first: missing {PVAULT}")

    def assert_secret_absent(self, secret: bytes, data: bytes | bytearray, location: str) -> None:
        if secret in data:
            self.fail(f"secret appeared in {location}")

    def recovery_secret(self, path: Path) -> bytes:
        for line in path.read_bytes().splitlines():
            if line.startswith(b"PV1R-"):
                return line
        self.fail("recovery file does not contain a PV1R value")

    def register_secrets(self, process: PtyProcess, secrets: Sequence[bytes]) -> None:
        for secret in secrets:
            process.register_secret(secret)

    def assert_invocation_clean(
        self,
        process: PtyProcess,
        secrets: Sequence[bytes],
    ) -> None:
        for secret in secrets:
            violations = invocation_contains_secret(process, secret)
            if violations:
                self.fail("secret appeared in " + ", ".join(violations))

    def finish_secret_process(
        self,
        process: PtyProcess,
        secrets: Sequence[bytes],
        *,
        expected_returncode: int = 0,
        timeout: float = 15.0,
    ) -> bytes:
        returncode = process.wait(timeout)
        for secret in secrets:
            self.assert_secret_absent(secret, process.output, "terminal output")
        self.assertTrue(process.echo_enabled(), "terminal echo was not restored")
        safe_output = process.safe_output()
        self.assertEqual(expected_returncode, returncode, safe_output)
        return safe_output

    def run_master_authenticated(
        self,
        vault: Path,
        arguments: Sequence[str | os.PathLike[str]],
        master_password: bytes,
        secrets: Sequence[bytes],
        *,
        environment: dict[str, str],
        selector: bytes | None = None,
        expected_returncode: int = 0,
    ) -> bytes:
        with PtyProcess(
            [PVAULT, "--vault", vault, *arguments],
            cwd=REPOSITORY,
            env=environment,
        ) as process:
            self.register_secrets(process, secrets)
            process.expect(b"Master password: ")
            self.assertFalse(process.echo_enabled())
            self.assert_invocation_clean(process, secrets)
            process.send_line(master_password)
            if selector is not None:
                process.expect(b"PVault search:")
                process.send_line(selector)
            return self.finish_secret_process(
                process,
                secrets,
                expected_returncode=expected_returncode,
            )

    def run_snapshot_password_authenticated(
        self,
        arguments: Sequence[str | os.PathLike[str]],
        master_password: bytes,
        secrets: Sequence[bytes],
        *,
        environment: dict[str, str],
        expected_returncode: int = 0,
    ) -> bytes:
        with PtyProcess(
            [PVAULT, *arguments],
            cwd=REPOSITORY,
            env=environment,
        ) as process:
            self.register_secrets(process, secrets)
            process.expect(b"Master password for snapshot: ")
            self.assertFalse(process.echo_enabled())
            self.assert_invocation_clean(process, secrets)
            process.send_line(master_password)
            return self.finish_secret_process(
                process,
                secrets,
                expected_returncode=expected_returncode,
            )

    def run_snapshot_recovery_authenticated(
        self,
        arguments: Sequence[str | os.PathLike[str]],
        secrets: Sequence[bytes],
        *,
        environment: dict[str, str],
        expected_returncode: int = 0,
    ) -> bytes:
        with PtyProcess(
            [PVAULT, *arguments],
            cwd=REPOSITORY,
            env=environment,
        ) as process:
            self.register_secrets(process, secrets)
            self.assert_invocation_clean(process, secrets)
            output = self.finish_secret_process(
                process,
                secrets,
                expected_returncode=expected_returncode,
            )
            self.assertNotIn(b"Master password for snapshot:", output)
            return output

    def snapshot_state(self, path: Path) -> tuple[bytes, int, int, int, int]:
        info = path.stat()
        return (
            path.read_bytes(),
            info.st_dev,
            info.st_ino,
            stat.S_IMODE(info.st_mode),
            info.st_nlink,
        )

    def assert_snapshot_state(
        self,
        path: Path,
        expected: tuple[bytes, int, int, int, int],
    ) -> None:
        self.assertEqual(expected, self.snapshot_state(path))

    def assert_snapshot_identity_only(self, output: bytes, record_count: int) -> None:
        normalized = output.replace(b"\r\n", b"\n")
        marker = b"Authenticated snapshot\n"
        self.assertIn(marker, normalized)
        identity = normalized[normalized.index(marker) :].strip().splitlines()
        self.assertEqual(
            6,
            len(identity),
            "rescue verify emitted fields outside its documented allowlist",
        )
        self.assertEqual(b"Authenticated snapshot", identity[0])
        self.assertEqual(b"Format: 1.0", identity[1])
        self.assertTrue(identity[2].startswith(b"Vault ID: "))
        self.assertEqual(32, len(identity[2].removeprefix(b"Vault ID: ")))
        self.assertTrue(identity[3].removeprefix(b"Generation: ").isdigit())
        self.assertEqual(f"Record count: {record_count}".encode("ascii"), identity[4])
        self.assertTrue(identity[5].startswith(b"Snapshot hash (BLAKE2b-256): "))
        self.assertEqual(
            64,
            len(identity[5].removeprefix(b"Snapshot hash (BLAKE2b-256): ")),
        )

    def change_master_password(
        self,
        vault: Path,
        new_password: bytes,
        secrets: Sequence[bytes],
        *,
        environment: dict[str, str],
        current_password: bytes | None = None,
        recovery_file: Path | None = None,
        expected_returncode: int = 0,
    ) -> bytes:
        if (current_password is None) == (recovery_file is None):
            raise ValueError("select exactly one password-change authentication path")

        arguments: list[str | os.PathLike[str]] = ["passwd"]
        if recovery_file is not None:
            arguments.extend(("--recovery", recovery_file))
        with PtyProcess(
            [PVAULT, "--vault", vault, *arguments],
            cwd=REPOSITORY,
            env=environment,
        ) as process:
            self.register_secrets(process, secrets)
            if current_password is not None:
                process.expect(b"Master password: ")
                self.assertFalse(process.echo_enabled())
                self.assert_invocation_clean(process, secrets)
                process.send_line(current_password)
            process.expect(b"New master password: ")
            self.assertFalse(process.echo_enabled())
            self.assert_invocation_clean(process, secrets)
            process.send_line(new_password)
            process.expect(b"Confirm: ")
            self.assertFalse(process.echo_enabled())
            process.send_line(new_password)
            return self.finish_secret_process(
                process,
                secrets,
                expected_returncode=expected_returncode,
            )

    def run_recovery_rejected(
        self,
        vault: Path,
        recovery_file: Path,
        secrets: Sequence[bytes],
        *,
        environment: dict[str, str],
    ) -> bytes:
        with PtyProcess(
            [PVAULT, "--vault", vault, "passwd", "--recovery", recovery_file],
            cwd=REPOSITORY,
            env=environment,
        ) as process:
            self.register_secrets(process, secrets)
            self.assert_invocation_clean(process, secrets)
            return self.finish_secret_process(
                process,
                secrets,
                expected_returncode=3,
            )

    def restore_backup(
        self,
        vault: Path,
        backup: Path,
        backup_password: bytes,
        secrets: Sequence[bytes],
        *,
        environment: dict[str, str],
    ) -> bytes:
        with PtyProcess(
            [PVAULT, "--vault", vault, "restore", backup],
            cwd=REPOSITORY,
            env=environment,
        ) as process:
            self.register_secrets(process, secrets)
            process.expect(b"Master password for backup: ")
            self.assertFalse(process.echo_enabled())
            self.assert_invocation_clean(process, secrets)
            process.send_line(backup_password)
            process.expect(b"Restore this authenticated backup? [y/N]: ")
            self.assertTrue(process.echo_enabled())
            process.send_line(b"y")
            return self.finish_secret_process(process, secrets)

    def test_tty_workflow_hides_secrets_and_redacts_show(self) -> None:
        master = b"PTY-Master-Secret-123!"
        record_secret = b"PTY-Record-Secret-456!"
        with tempfile.TemporaryDirectory(prefix="pvault-pty-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            environment = isolated_environment(root)
            vault = root / "vault\nINIT-VAULT-PATH-MARKER\x1b[31m'quoted.pvlt"
            recovery = root / "recovery\nINIT-RECOVERY-PATH-MARKER\x1b]8;;bad'quoted.txt"

            init_output = initialize_vault(
                PVAULT,
                vault,
                recovery,
                master,
                cwd=REPOSITORY,
                env=environment,
            )
            self.assertIn(b"Vault created at the requested vault path", init_output)
            self.assertNotIn(b"INIT-VAULT-PATH-MARKER", init_output)
            self.assertNotIn(b"INIT-RECOVERY-PATH-MARKER", init_output)
            self.assertNotIn(b"\x1b", init_output)
            self.assertNotIn(os.fsencode(vault), init_output)
            self.assertNotIn(os.fsencode(recovery), init_output)
            add_output = add_record(
                PVAULT,
                vault,
                master,
                record_secret,
                title=b"PTY Account",
                username=b"pty-user",
                cwd=REPOSITORY,
                env=environment,
            )
            self.assertIn(b"Record added", add_output)

            output = self.run_master_authenticated(
                vault,
                ("show",),
                master,
                (master, record_secret),
                environment=environment,
                selector=b"PTY",
            )
            self.assertIn(b"Title: PTY Account", output)
            self.assertIn(b"Username: pty-user", output)
            self.assertIn(b"Password: <secret>", output)

            vault_bytes = vault.read_bytes()
            self.assert_secret_absent(master, vault_bytes, "encrypted vault bytes")
            self.assert_secret_absent(record_secret, vault_bytes, "encrypted vault bytes")
            self.assertEqual(0o600, stat.S_IMODE(vault.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(recovery.stat().st_mode))

    def test_legacy_record_selectors_fail_before_unlock_without_echoing(self) -> None:
        selector = b"LEGACY-SELECTOR-ARGV-CANARY"
        with tempfile.TemporaryDirectory(prefix="pvault-legacy-selector-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            environment = isolated_environment(root)
            vault = root / "unused-vault.pvlt"

            for command in ("edit", "remove", "list", "show", "copy"):
                with self.subTest(command=command):
                    with PtyProcess(
                        [PVAULT, "--vault", vault, command, selector.decode("ascii")],
                        cwd=REPOSITORY,
                        env=environment,
                    ) as process:
                        process.register_secret(selector)
                        returncode = process.wait(5.0)
                        output = bytes(process.output)

                        self.assertEqual(2, returncode, process.safe_output())
                        self.assertNotIn(b"Master password: ", output)
                        self.assertNotIn(selector, output)
                        self.assertIn(b"positional record selectors are disabled", output)
                        self.assertTrue(process.echo_enabled())

    def test_private_metadata_output_is_gated_before_unlock(self) -> None:
        master = b"Redirect-Gate-Master-Secret-123!"
        record_secret = b"Redirect-Gate-Record-Secret-456!"
        title = b"PRIVATE-OUTPUT-TITLE-CANARY"
        username = b"PRIVATE-OUTPUT-USERNAME-CANARY"
        secrets = (master, record_secret, title, username)

        with tempfile.TemporaryDirectory(prefix="pvault-output-gate-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            environment = isolated_environment(root)
            vault = root / "vault.pvlt"
            recovery = root / "recovery.txt"
            initialize_vault(
                PVAULT,
                vault,
                recovery,
                master,
                cwd=REPOSITORY,
                env=environment,
            )
            add_record(
                PVAULT,
                vault,
                master,
                record_secret,
                title=title,
                username=username,
                cwd=REPOSITORY,
                env=environment,
            )

            for arguments in (("list",), ("show",), ("pick",), ("shell",)):
                with self.subTest(command=arguments[0]):
                    with SplitPtyProcess(
                        [PVAULT, "--vault", vault, *arguments],
                        cwd=REPOSITORY,
                        env=environment,
                    ) as process:
                        self.register_secrets(process, secrets)
                        self.assert_invocation_clean(process, secrets)
                        returncode = process.wait(5.0)
                        terminal_output = bytes(process.output)
                        redirected_stdout = bytes(process.stdout)

                        self.assertEqual(2, returncode, process.safe_output())
                        self.assertEqual(b"", redirected_stdout)
                        self.assertNotIn(b"Master password: ", terminal_output)
                        self.assertIn(b"redirect", terminal_output)
                        for secret in secrets:
                            self.assert_secret_absent(
                                secret,
                                terminal_output,
                                "redirect refusal terminal output",
                            )
                            self.assert_secret_absent(
                                secret,
                                redirected_stdout,
                                "refused redirected stdout",
                            )
                        self.assertTrue(process.echo_enabled())

            with SplitPtyProcess(
                [PVAULT, "--vault", vault, "list", "--allow-redirect"],
                cwd=REPOSITORY,
                env=environment,
            ) as process:
                self.register_secrets(process, secrets)
                process.expect(b"Master password: ")
                self.assertEqual(b"", bytes(process.stdout))
                self.assertFalse(process.echo_enabled())
                self.assert_invocation_clean(process, secrets)
                process.send_line(master)
                returncode = process.wait(15.0)
                terminal_output = bytes(process.output)
                redirected_stdout = bytes(process.stdout)

                self.assertEqual(0, returncode, process.safe_output())
                self.assertIn(title, redirected_stdout)
                self.assertIn(username, redirected_stdout)
                self.assertIn(b"1 record", redirected_stdout)
                self.assert_secret_absent(master, terminal_output, "terminal output")
                self.assert_secret_absent(master, redirected_stdout, "redirected stdout")
                self.assert_secret_absent(
                    record_secret,
                    terminal_output,
                    "terminal output",
                )
                self.assert_secret_absent(
                    record_secret,
                    redirected_stdout,
                    "redirected stdout",
                )
                self.assertTrue(process.echo_enabled())

    def test_rofi_boundary_resets_process_state_and_uses_ephemeral_token(self) -> None:
        if not ROFI_TEST_PVAULT.is_file() or not SIGNAL_LAUNCHER.is_file():
            self.skipTest("test-only rofi CLI and signal launcher are unavailable")

        master = b"Rofi-Boundary-Master-Secret-123!"
        record_secret = b"Rofi-Boundary-Record-Secret-456!"
        title = b"ROFI-TITLE-\x1b[31m-CANARY"
        sanitized_title = b"ROFI-TITLE-?[31m-CANARY"
        username = b"ROFI-USERNAME-CANARY"
        secrets = (master, record_secret, title, username)

        with tempfile.TemporaryDirectory(prefix="pvault-rofi-boundary-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            environment = isolated_environment(root)
            environment["DISPLAY"] = ":99"
            environment["PATH"] = "/definitely/not-the-rofi-path"
            vault = root / "vault.pvlt"
            recovery = root / "recovery.txt"
            (Path(environment["HOME"]) / "fake-rofi.expected-title").write_bytes(
                sanitized_title + b"\n"
            )

            initialize_vault(
                PVAULT,
                vault,
                recovery,
                master,
                cwd=REPOSITORY,
                env=environment,
            )
            add_record(
                PVAULT,
                vault,
                master,
                record_secret,
                title=title,
                username=username,
                cwd=REPOSITORY,
                env=environment,
            )

            def run_rofi(expected_returncode: int) -> bytes:
                with PtyProcess(
                    [
                        SIGNAL_LAUNCHER,
                        ROFI_TEST_PVAULT,
                        "--vault",
                        vault,
                        "pick",
                        "--rofi",
                    ],
                    cwd=REPOSITORY,
                    env=environment,
                ) as process:
                    self.register_secrets(process, (master, record_secret))
                    process.expect(b"Master password: ")
                    self.assertFalse(process.echo_enabled())
                    self.assert_invocation_clean(process, secrets)
                    process.send_line(master)
                    return self.finish_secret_process(
                        process,
                        (master, record_secret),
                        expected_returncode=expected_returncode,
                        timeout=20.0,
                    )

            for _ in range(2):
                output = run_rofi(0)
                self.assertIn(b"Title: " + sanitized_title, output)
                self.assertIn(b"Username: " + username, output)
                self.assertIn(b"Password: <secret>", output)
                self.assertNotIn(title, output)
            tokens = (Path(environment["HOME"]) / "fake-rofi.tokens").read_text(
                encoding="ascii"
            ).splitlines()
            self.assertEqual(2, len(tokens))
            self.assertNotEqual(tokens[0], tokens[1])
            self.assertTrue(all(len(token) == 16 for token in tokens))

            mode_path = Path(environment["HOME"]) / "fake-rofi.mode"
            for mode in ("unknown", "extra-tab", "truncated"):
                with self.subTest(rofi_response=mode):
                    mode_path.write_text(mode + "\n", encoding="ascii")
                    rejected = run_rofi(1)
                    self.assertIn(b"record not found", rejected)

            mode_path.write_text("ignore-term\n", encoding="ascii")
            failed = run_rofi(7)
            self.assertIn(b"external integration failed", failed)
            fake_pid = int(
                (Path(environment["HOME"]) / "fake-rofi.pid").read_text(
                    encoding="ascii"
                )
            )
            wait_until(lambda: not pid_exists(fake_pid), 5.0, "fake rofi KILL cleanup")

    def test_copy_selects_duplicate_custom_field_by_private_ordinal(self) -> None:
        if not ROFI_TEST_PVAULT.is_file():
            self.skipTest("test-only private CLI is unavailable")

        master = b"Custom-Ordinal-Master-Secret-123!"
        record_password = b"Custom-Ordinal-Record-Secret-456!"
        first_value = b"Custom-Ordinal-First-Secret-789!"
        second_value = b"Custom-Ordinal-Second-Secret-012!"
        title = b"Duplicate Custom Fixture"
        field_name = b"Duplicate Field"
        protected = (master, record_password, first_value, second_value)

        with tempfile.TemporaryDirectory(prefix="pvault-custom-ordinal-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            environment = isolated_environment(root)
            environment["DISPLAY"] = ":99"
            vault = root / "vault.pvlt"
            recovery = root / "recovery.txt"
            home = Path(environment["HOME"])

            initialize_vault(
                PVAULT,
                vault,
                recovery,
                master,
                cwd=REPOSITORY,
                env=environment,
            )
            with PtyProcess(
                [PVAULT, "--vault", vault, "add"],
                cwd=REPOSITORY,
                env=environment,
            ) as process:
                self.register_secrets(process, protected)
                process.expect(b"Master password: ")
                process.send_line(master)
                process.expect(b"Title: ")
                process.send_line(title)
                process.expect(b"Username: ")
                process.send_line(b"duplicate-user")
                process.expect(b"Password [g=generate/e=enter] (g): ")
                process.send_line(b"e")
                process.expect(b"Password: ")
                process.send_line(record_password)
                process.expect(b"URLs (comma-separated): ")
                process.send_line(b"")
                process.expect(b"Notes (single line): ")
                process.send_line(b"")
                process.expect(b"Tags (comma-separated): ")
                process.send_line(b"")
                process.expect(b"Custom fields count [0]: ")
                process.send_line(b"2")
                for index, value in enumerate((first_value, second_value), start=1):
                    process.expect(f"Custom field {index} name: ".encode("ascii"))
                    process.send_line(field_name)
                    process.expect(b"Secret value? [y/N]: ")
                    process.send_line(b"y")
                    process.expect(f"Custom field {index} value: ".encode("ascii"))
                    process.send_line(value)
                add_output = self.finish_secret_process(process, protected)
            self.assertIn(b"Record added", add_output)

            with SplitPtyProcess(
                [
                    ROFI_TEST_PVAULT,
                    "--vault",
                    vault,
                    "copy",
                    "--field",
                    "custom",
                    "--ttl",
                    "1",
                ],
                cwd=REPOSITORY,
                env=environment,
            ) as process:
                self.register_secrets(process, protected)
                process.expect(b"Master password: ")
                self.assert_invocation_clean(process, (*protected, title, field_name))
                process.send_line(master)
                process.expect(b"PVault search:")
                process.send_line(b"Duplicate Custom")
                process.expect(b"Custom fields:")
                process.expect(b"1. Duplicate Field")
                process.expect(b"2. Duplicate Field")
                process.expect(b"Custom field number: ")
                process.send_line(b"2")
                returncode = process.wait(20.0)
                terminal_output = bytes(process.output)
                redirected_stdout = bytes(process.stdout)
                self.assertEqual(0, returncode, process.safe_output())
                self.assertTrue(process.echo_enabled())

            self.assertIn(b"1. Duplicate Field", terminal_output)
            self.assertIn(b"2. Duplicate Field", terminal_output)
            self.assertNotIn(field_name, redirected_stdout)
            self.assertIn(b"Requested field queued", redirected_stdout)
            for value in protected:
                self.assertNotIn(value, terminal_output)
                self.assertNotIn(value, redirected_stdout)
            result_path = home / "result.json"
            wait_until(result_path.is_file, 5.0, "fake clipboard result")
            result = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertEqual(len(second_value), result["length"])
            self.assertEqual(sha256(second_value).hexdigest(), result["sha256"])
            self.assertFalse(result["secret_in_argv"])
            self.assertFalse(result["secret_in_cmdline"])
            self.assertFalse(result["secret_in_environment"])
            self.assertTrue(result["sigchld_default"])
            self.assertFalse(result["sigterm_blocked"])
            owner_pid = int((home / "owner.pid").read_text(encoding="ascii"))
            wait_until(lambda: not pid_exists(owner_pid), 5.0, "fake clipboard owner cleanup")

    def test_remove_cancel_keeps_identity_on_tty_and_stdout_generic(self) -> None:
        master = b"Remove-Cancel-Master-Secret-123!"
        record_secret = b"Remove-Cancel-Record-Secret-456!"
        title = b"REMOVE-TITLE-\x1b[31m-CANARY"
        sanitized_title = b"REMOVE-TITLE-?[31m-CANARY"
        username = b"REMOVE-USERNAME-CANARY"
        secrets = (master, record_secret, title, username)

        with tempfile.TemporaryDirectory(prefix="pvault-remove-cancel-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            environment = isolated_environment(root)
            vault = root / "vault.pvlt"
            recovery = root / "recovery.txt"

            initialize_vault(
                PVAULT,
                vault,
                recovery,
                master,
                cwd=REPOSITORY,
                env=environment,
            )
            add_record(
                PVAULT,
                vault,
                master,
                record_secret,
                title=title,
                username=username,
                cwd=REPOSITORY,
                env=environment,
            )
            vault_before = vault.read_bytes()

            with SplitPtyProcess(
                [PVAULT, "--vault", vault, "remove"],
                cwd=REPOSITORY,
                env=environment,
            ) as process:
                self.register_secrets(process, secrets)
                process.expect(b"Master password: ")
                self.assertFalse(process.echo_enabled())
                self.assert_invocation_clean(process, secrets)
                process.send_line(master)
                process.expect(b"PVault search:")
                process.send_line(b"REMOVE-TITLE")
                process.expect(b"Selected for deletion: " + sanitized_title)
                process.expect(b"Delete the selected record [y/N]: ")
                self.assertTrue(process.echo_enabled())
                process.send_line(b"N")
                returncode = process.wait(15.0)
                terminal_output = bytes(process.output)
                redirected_stdout = bytes(process.stdout)

                self.assertEqual(0, returncode, process.safe_output())
                self.assertEqual(b"Deletion cancelled\n", redirected_stdout)
                self.assertIn(b"Selected for deletion: " + sanitized_title, terminal_output)
                self.assertNotIn(title, terminal_output)
                self.assertNotIn(title, redirected_stdout)
                self.assertNotIn(sanitized_title, redirected_stdout)
                self.assertNotIn(username, redirected_stdout)
                self.assert_secret_absent(master, terminal_output, "remove terminal output")
                self.assert_secret_absent(master, redirected_stdout, "remove stdout")
                self.assert_secret_absent(
                    record_secret,
                    terminal_output,
                    "remove terminal output",
                )
                self.assert_secret_absent(
                    record_secret,
                    redirected_stdout,
                    "remove stdout",
                )
                self.assertTrue(process.echo_enabled())

            self.assertEqual(vault_before, vault.read_bytes())
            list_output = self.run_master_authenticated(
                vault,
                ("list",),
                master,
                (master, record_secret),
                environment=environment,
            )
            self.assertIn(b"1 record", list_output)
            self.assertIn(sanitized_title, list_output)
            self.assertIn(username, list_output)

    def test_master_password_policy_is_shared_by_init_and_passwd(self) -> None:
        policy_message = (
            b"master password must be at least 16 bytes and not a common value, "
            b"full sequence, or periodic repetition; prefer a randomly generated "
            b"5-6 word passphrase"
        )
        rejected_passwords = (
            b"aB3$dE6&gH9*kL?",
            b"correcthorsebatterystaple",
            b"abcdefghijklmnop",
            b"Ab9!Ab9!Ab9!Ab9!",
        )

        with tempfile.TemporaryDirectory(prefix="pvault-master-policy-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            environment = isolated_environment(root)

            for index, password in enumerate(rejected_passwords):
                with self.subTest(password_class=index):
                    vault = root / f"rejected-{index}.pvlt"
                    recovery = root / f"rejected-{index}.txt"
                    with PtyProcess(
                        [PVAULT, "--vault", vault, "init", "--recovery-out", recovery],
                        cwd=REPOSITORY,
                        env=environment,
                    ) as process:
                        process.register_secret(password)
                        process.expect(b"New master password: ")
                        self.assertFalse(process.echo_enabled())
                        process.send_line(password)
                        process.expect(b"Confirm: ")
                        self.assertFalse(process.echo_enabled())
                        process.send_line(password)
                        output = self.finish_secret_process(
                            process,
                            (password,),
                            expected_returncode=2,
                        )
                    self.assertIn(policy_message, output)
                    self.assertFalse(vault.exists())
                    self.assertFalse(recovery.exists())

            vault = root / "accepted.pvlt"
            recovery = root / "accepted-recovery.txt"
            current_password = b"Random-Master-Passphrase-729!"
            initialize_vault(
                PVAULT,
                vault,
                recovery,
                current_password,
                cwd=REPOSITORY,
                env=environment,
            )
            passwd_output = self.change_master_password(
                vault,
                rejected_passwords[1],
                (current_password, rejected_passwords[1]),
                environment=environment,
                current_password=current_password,
                expected_returncode=2,
            )
            self.assertIn(policy_message, passwd_output)
            self.run_master_authenticated(
                vault,
                ("list",),
                current_password,
                (current_password,),
                environment=environment,
            )

    def test_password_change_recovery_rotation_and_recovery_password_change(self) -> None:
        original_master = b"Original-Master-Secret-101!"
        rotated_master = b"Rotated-Master-Secret-202!"
        recovered_master = b"Recovered-Master-Secret-303!"
        record_secret = b"Credential-Secret-Survives-Rotation-404!"
        all_secrets = (
            original_master,
            rotated_master,
            recovered_master,
            record_secret,
        )

        with tempfile.TemporaryDirectory(prefix="pvault-credentials-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            environment = isolated_environment(root)
            vault = root / "vault.pvlt"
            original_recovery = root / "recovery-original.txt"
            rotated_recovery = root / "recovery-rotated\nROTATE-PATH-MARKER\x1b[31m'quoted.txt"

            initialize_vault(
                PVAULT,
                vault,
                original_recovery,
                original_master,
                cwd=REPOSITORY,
                env=environment,
            )
            add_record(
                PVAULT,
                vault,
                original_master,
                record_secret,
                title=b"Rotation Fixture",
                username=b"fixture-user",
                cwd=REPOSITORY,
                env=environment,
            )

            passwd_output = self.change_master_password(
                vault,
                rotated_master,
                all_secrets,
                environment=environment,
                current_password=original_master,
            )
            self.assertIn(b"Master password updated", passwd_output)

            rejected_output = self.run_master_authenticated(
                vault,
                ("list",),
                original_master,
                all_secrets,
                environment=environment,
                expected_returncode=3,
            )
            self.assertIn(b"authentication or integrity check failed", rejected_output)
            show_output = self.run_master_authenticated(
                vault,
                ("show",),
                rotated_master,
                all_secrets,
                environment=environment,
                selector=b"Rotation Fixture",
            )
            self.assertIn(b"Title: Rotation Fixture", show_output)
            self.assertIn(b"Password: <secret>", show_output)

            rotate_output = self.run_master_authenticated(
                vault,
                ("recovery", "rotate", "--out", rotated_recovery),
                rotated_master,
                all_secrets,
                environment=environment,
            )
            self.assertIn(b"Recovery key rotated", rotate_output)
            self.assertNotIn(b"ROTATE-PATH-MARKER", rotate_output)
            self.assertNotIn(b"\x1b", rotate_output)
            self.assertNotIn(os.fsencode(rotated_recovery), rotate_output)
            self.assertTrue(rotated_recovery.is_file())
            self.assertEqual(0o600, stat.S_IMODE(rotated_recovery.stat().st_mode))

            old_recovery_output = self.run_recovery_rejected(
                vault,
                original_recovery,
                all_secrets,
                environment=environment,
            )
            self.assertIn(
                b"authentication or integrity check failed",
                old_recovery_output,
            )
            recovery_output = self.change_master_password(
                vault,
                recovered_master,
                all_secrets,
                environment=environment,
                recovery_file=rotated_recovery,
            )
            self.assertIn(b"Master password updated", recovery_output)

            former_master_output = self.run_master_authenticated(
                vault,
                ("list",),
                rotated_master,
                all_secrets,
                environment=environment,
                expected_returncode=3,
            )
            self.assertIn(
                b"authentication or integrity check failed",
                former_master_output,
            )
            final_output = self.run_master_authenticated(
                vault,
                ("show",),
                recovered_master,
                all_secrets,
                environment=environment,
                selector=b"Rotation Fixture",
            )
            self.assertIn(b"Title: Rotation Fixture", final_output)
            self.assertIn(b"Username: fixture-user", final_output)
            self.assertIn(b"Password: <secret>", final_output)

            vault_bytes = vault.read_bytes()
            for secret in all_secrets:
                self.assert_secret_absent(secret, vault_bytes, "rotated vault bytes")
            self.assertEqual(0o600, stat.S_IMODE(vault.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(original_recovery.stat().st_mode))
            self.assertEqual(0o700, stat.S_IMODE(root.stat().st_mode))

    def test_backup_and_authenticated_restore_roll_back_synthetic_mutation(self) -> None:
        master = b"Backup-Restore-Master-Secret-505!"
        retained_secret = b"Retained-Record-Secret-606!"
        rolled_back_secret = b"Rolled-Back-Record-Secret-707!"
        all_secrets = (master, retained_secret, rolled_back_secret)

        with tempfile.TemporaryDirectory(prefix="pvault-restore-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            environment = isolated_environment(root)
            vault = root / "vault.pvlt"
            recovery = root / "recovery.txt"
            backup = root / "manual-backup\nBACKUP-PATH-MARKER\x1b[31m'quoted.pvlt"

            initialize_vault(
                PVAULT,
                vault,
                recovery,
                master,
                cwd=REPOSITORY,
                env=environment,
            )
            add_record(
                PVAULT,
                vault,
                master,
                retained_secret,
                title=b"Retained Fixture",
                username=b"retained-user",
                cwd=REPOSITORY,
                env=environment,
            )
            backup_output = self.run_master_authenticated(
                vault,
                ("backup", "--output", backup),
                master,
                all_secrets,
                environment=environment,
            )
            self.assertIn(b"Encrypted backup written", backup_output)
            self.assertNotIn(b"BACKUP-PATH-MARKER", backup_output)
            self.assertNotIn(b"\x1b", backup_output)
            self.assertNotIn(os.fsencode(backup), backup_output)
            self.assertTrue(backup.is_file())
            self.assertEqual(0o600, stat.S_IMODE(backup.stat().st_mode))
            backup_digest = sha256(backup.read_bytes()).digest()

            add_record(
                PVAULT,
                vault,
                master,
                rolled_back_secret,
                title=b"Rolled Back Fixture",
                username=b"rollback-user",
                cwd=REPOSITORY,
                env=environment,
            )
            mutated_output = self.run_master_authenticated(
                vault,
                ("list",),
                master,
                all_secrets,
                environment=environment,
            )
            self.assertIn(b"Retained Fixture", mutated_output)
            self.assertIn(b"Rolled Back Fixture", mutated_output)
            self.assertIn(b"2 records", mutated_output)

            restore_output = self.restore_backup(
                vault,
                backup,
                master,
                all_secrets,
                environment=environment,
            )
            self.assertIn(b"Vault restored from the authenticated backup", restore_output)
            self.assertNotIn(b"BACKUP-PATH-MARKER", restore_output)
            self.assertNotIn(b"\x1b", restore_output)
            self.assertNotIn(os.fsencode(backup), restore_output)
            restored_output = self.run_master_authenticated(
                vault,
                ("list",),
                master,
                all_secrets,
                environment=environment,
            )
            self.assertIn(b"Retained Fixture", restored_output)
            self.assertNotIn(b"Rolled Back Fixture", restored_output)
            self.assertIn(b"1 record", restored_output)
            retained_output = self.run_master_authenticated(
                vault,
                ("show",),
                master,
                all_secrets,
                environment=environment,
                selector=b"Retained Fixture",
            )
            self.assertIn(b"Username: retained-user", retained_output)
            self.assertIn(b"Password: <secret>", retained_output)

            self.assertEqual(backup_digest, sha256(backup.read_bytes()).digest())
            encrypted_paths = [vault, backup, *root.glob("backups/*.pvlt")]
            self.assertGreaterEqual(len(encrypted_paths), 3)
            for path in encrypted_paths:
                encrypted_bytes = path.read_bytes()
                for secret in all_secrets:
                    self.assert_secret_absent(
                        secret,
                        encrypted_bytes,
                        "encrypted vault or backup bytes",
                    )
                self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(0o700, stat.S_IMODE((root / "backups").stat().st_mode))

    def test_rescue_inspect_verify_recover_and_rollback_are_non_mutating(self) -> None:
        master = b"Rescue-PTY-Master-Secret-808!"
        retained_secret = b"Rescue-Retained-Record-Secret-909!"
        active_only_secret = b"Rescue-Active-Only-Secret-010!"

        with tempfile.TemporaryDirectory(prefix="pvault-rescue-pty-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            environment = isolated_environment(root)
            vault = root / "active.pvlt"
            recovery = root / "recovery.txt"
            source = root / "pre-migration.pvlt"
            recovered = root / "recovered-read-only.pvlt"
            rollback = root / "rollback-read-only.pvlt"
            hostile_output = root / "copy\nPATH-INJECTION-MARKER\x1b[31m'quoted.pvlt"

            initialize_vault(
                PVAULT,
                vault,
                recovery,
                master,
                cwd=REPOSITORY,
                env=environment,
            )
            add_record(
                PVAULT,
                vault,
                master,
                retained_secret,
                title=b"Rescue Retained Fixture",
                username=b"rescue-retained-user",
                cwd=REPOSITORY,
                env=environment,
            )
            initial_secrets = (master, retained_secret, active_only_secret)
            backup_output = self.run_master_authenticated(
                vault,
                ("backup", "--output", source),
                master,
                initial_secrets,
                environment=environment,
            )
            self.assertIn(b"Encrypted backup written", backup_output)
            add_record(
                PVAULT,
                vault,
                master,
                active_only_secret,
                title=b"Active Only Fixture",
                username=b"active-only-user",
                cwd=REPOSITORY,
                env=environment,
            )

            recovery_secret = self.recovery_secret(recovery)
            all_secrets = (
                master,
                retained_secret,
                active_only_secret,
                recovery_secret,
            )
            source_state = self.snapshot_state(source)
            active_state = self.snapshot_state(vault)
            self.assertEqual(0o600, source_state[3])
            self.assertEqual(0o600, active_state[3])

            config_directory = Path(environment["XDG_CONFIG_HOME"]) / "pvault"
            config_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            (config_directory / "config").write_text(
                "this line is deliberately invalid\n",
                encoding="ascii",
            )

            with PtyProcess(
                [PVAULT, "rescue", "inspect", source],
                cwd=REPOSITORY,
                env=environment,
            ) as process:
                self.register_secrets(process, all_secrets)
                self.assert_invocation_clean(process, all_secrets)
                inspect_output = self.finish_secret_process(process, all_secrets)
            self.assertIn(b"UNAUTHENTICATED snapshot metadata", inspect_output)
            self.assertIn(b"Format (UNAUTHENTICATED): 1.0", inspect_output)
            self.assertIn(b"Vault ID (UNAUTHENTICATED):", inspect_output)
            self.assertIn(b"Ciphertext bytes (UNAUTHENTICATED):", inspect_output)
            self.assertNotIn(b"Master password", inspect_output)
            self.assertNotIn(b"hash", inspect_output.lower())
            self.assert_snapshot_state(source, source_state)
            self.assert_snapshot_state(vault, active_state)

            with SplitPtyProcess(
                [PVAULT, "rescue", "verify", source],
                cwd=REPOSITORY,
                env=environment,
            ) as process:
                self.register_secrets(process, all_secrets)
                self.assert_invocation_clean(process, all_secrets)
                returncode = process.wait(5.0)
                terminal_output = bytes(process.output)
                redirected_stdout = bytes(process.stdout)

                self.assertEqual(2, returncode, process.safe_output())
                self.assertEqual(b"", redirected_stdout)
                self.assertNotIn(b"Master password for snapshot: ", terminal_output)
                self.assertIn(b"refusing to emit decrypted record metadata", terminal_output)
                for secret in all_secrets:
                    self.assert_secret_absent(
                        secret,
                        terminal_output,
                        "rescue verify redirect refusal",
                    )
                    self.assert_secret_absent(
                        secret,
                        redirected_stdout,
                        "refused rescue verify stdout",
                    )
                self.assertTrue(process.echo_enabled())

            with SplitPtyProcess(
                [PVAULT, "rescue", "verify", source, "--allow-redirect"],
                cwd=REPOSITORY,
                env=environment,
            ) as process:
                self.register_secrets(process, all_secrets)
                process.expect(b"Master password for snapshot: ")
                self.assertEqual(b"", bytes(process.stdout))
                self.assertFalse(process.echo_enabled())
                self.assert_invocation_clean(process, all_secrets)
                process.send_line(master)
                returncode = process.wait(15.0)
                terminal_output = bytes(process.output)
                redirected_stdout = bytes(process.stdout)

                self.assertEqual(0, returncode, process.safe_output())
                self.assert_snapshot_identity_only(redirected_stdout, 1)
                self.assertNotIn(b"Rescue Retained Fixture", redirected_stdout)
                self.assertNotIn(b"rescue-retained-user", redirected_stdout)
                for secret in all_secrets:
                    self.assert_secret_absent(
                        secret,
                        terminal_output,
                        "rescue verify terminal output",
                    )
                    self.assert_secret_absent(
                        secret,
                        redirected_stdout,
                        "authenticated snapshot identity",
                    )
                self.assertTrue(process.echo_enabled())

            self.assert_snapshot_state(source, source_state)
            self.assert_snapshot_state(vault, active_state)

            password_verify = self.run_snapshot_password_authenticated(
                ("rescue", "verify", source),
                master,
                all_secrets,
                environment=environment,
            )
            self.assertIn(b"Authenticated snapshot", password_verify)
            self.assertIn(b"Format: 1.0", password_verify)
            self.assertIn(b"Generation:", password_verify)
            self.assertIn(b"Record count: 1", password_verify)
            self.assertIn(b"Snapshot hash (BLAKE2b-256):", password_verify)
            self.assert_snapshot_identity_only(password_verify, 1)
            self.assertNotIn(b"Rescue Retained Fixture", password_verify)
            self.assertNotIn(b"rescue-retained-user", password_verify)

            recovery_verify = self.run_snapshot_recovery_authenticated(
                ("rescue", "verify", source, "--recovery", recovery),
                all_secrets,
                environment=environment,
            )
            self.assertIn(b"Authenticated snapshot", recovery_verify)
            self.assertIn(b"Record count: 1", recovery_verify)
            self.assert_snapshot_identity_only(recovery_verify, 1)
            self.assertNotIn(b"Rescue Retained Fixture", recovery_verify)
            self.assertNotIn(b"rescue-retained-user", recovery_verify)

            recover_output = self.run_snapshot_recovery_authenticated(
                (
                    "rescue",
                    "recover",
                    source,
                    "--output",
                    recovered,
                    "--recovery",
                    recovery,
                ),
                all_secrets,
                environment=environment,
            )
            self.assertIn(b"Authenticated recovery copy written", recover_output)
            self.assertIn(b"active vault and source snapshot were left unchanged", recover_output)
            self.assertEqual(source_state[0], recovered.read_bytes())
            self.assertEqual(0o400, stat.S_IMODE(recovered.stat().st_mode))
            recovered_verify = self.run_snapshot_password_authenticated(
                ("rescue", "verify", recovered),
                master,
                all_secrets,
                environment=environment,
            )
            self.assertIn(b"Authenticated snapshot", recovered_verify)
            self.assertIn(b"Record count: 1", recovered_verify)

            rollback_output = self.run_snapshot_password_authenticated(
                ("rollback", source, "--output", rollback),
                master,
                all_secrets,
                environment=environment,
            )
            self.assertIn(b"Authenticated rollback copy written", rollback_output)
            self.assertIn(b"active vault and source snapshot were left unchanged", rollback_output)
            self.assertEqual(source_state[0], rollback.read_bytes())
            self.assertEqual(0o400, stat.S_IMODE(rollback.stat().st_mode))
            rollback_verify = self.run_snapshot_recovery_authenticated(
                ("rescue", "verify", rollback, "--recovery", recovery),
                all_secrets,
                environment=environment,
            )
            self.assertIn(b"Authenticated snapshot", rollback_verify)
            self.assertIn(b"Record count: 1", rollback_verify)

            hostile_output_text = self.run_snapshot_recovery_authenticated(
                (
                    "rescue",
                    "recover",
                    source,
                    "--output",
                    hostile_output,
                    "--recovery",
                    recovery,
                ),
                all_secrets,
                environment=environment,
            )
            self.assertIn(b"Authenticated recovery copy written", hostile_output_text)
            self.assertNotIn(b"PATH-INJECTION-MARKER", hostile_output_text)
            self.assertNotIn(b"\x1b", hostile_output_text)
            self.assertNotIn(os.fsencode(hostile_output), hostile_output_text)
            self.assertEqual(source_state[0], hostile_output.read_bytes())
            self.assertEqual(0o400, stat.S_IMODE(hostile_output.stat().st_mode))

            self.assert_snapshot_state(source, source_state)
            self.assert_snapshot_state(vault, active_state)
            for path in (source, vault, recovered, rollback, hostile_output):
                encrypted = path.read_bytes()
                for secret in all_secrets:
                    self.assert_secret_absent(secret, encrypted, f"encrypted bytes at {path}")

            help_result = subprocess.run(
                [PVAULT, "help", "rescue"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=REPOSITORY,
                timeout=5.0,
                check=False,
            )
            self.assertEqual(0, help_result.returncode, help_result.stderr)
            self.assertIn(b"Usage: pvault rescue inspect", help_result.stdout)
            self.assertIn(
                b"pvault rescue verify SNAPSHOT [--recovery FILE] [--allow-redirect]",
                help_result.stdout,
            )
            for arguments, expected_usage in (
                (
                    ("list", "--help"),
                    b"Usage: pvault [--vault PATH] list [--allow-redirect]",
                ),
                (("config", "--help"), b"Usage: pvault config check"),
                (("rescue", "inspect", "--help"), b"Usage: pvault rescue inspect SNAPSHOT"),
                (
                    ("rescue", "verify", "--help"),
                    b"Usage: pvault rescue verify SNAPSHOT "
                    b"[--recovery FILE] [--allow-redirect]",
                ),
                (
                    ("recovery", "rotate", "--help"),
                    b"Usage: pvault [--vault PATH] recovery rotate --out PATH",
                ),
            ):
                command_help = subprocess.run(
                    [PVAULT, *arguments],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=environment,
                    cwd=REPOSITORY,
                    timeout=5.0,
                    check=False,
                )
                self.assertEqual(0, command_help.returncode, command_help.stderr)
                self.assertIn(expected_usage, command_help.stdout)
            version_result = subprocess.run(
                [PVAULT, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=REPOSITORY,
                timeout=5.0,
                check=False,
            )
            self.assertEqual(0, version_result.returncode, version_result.stderr)
            self.assertIn(b"pvault 0.1.0-pre-alpha", version_result.stdout)
            help_as_value_result = subprocess.run(
                [PVAULT, "--vault", vault, "copy", "fixture", "--field", "--help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=REPOSITORY,
                timeout=5.0,
                check=False,
            )
            self.assertNotEqual(0, help_as_value_result.returncode)
            self.assertNotIn(b"Usage: pvault copy", help_as_value_result.stdout)
            invalid_config_check = subprocess.run(
                [PVAULT, "config", "check"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=REPOSITORY,
                timeout=5.0,
                check=False,
            )
            self.assertNotEqual(0, invalid_config_check.returncode)
            self.assertIn(b"pvault: configuration:", invalid_config_check.stderr)
            self.assertNotIn(os.fsencode(config_directory), invalid_config_check.stderr)
            config_path = config_directory / "config"
            config_path.write_text("clipboard_ttl_seconds=10\n", encoding="ascii")
            config_path.chmod(0o600)
            valid_config_check = subprocess.run(
                [PVAULT, "config", "check"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=REPOSITORY,
                timeout=5.0,
                check=False,
            )
            self.assertEqual(0, valid_config_check.returncode, valid_config_check.stderr)
            self.assertIn(b"Configuration check passed", valid_config_check.stdout)
            self.assertNotIn(os.fsencode(config_directory), valid_config_check.stdout)
            for secret in all_secrets:
                self.assert_secret_absent(
                    secret,
                    help_result.stdout
                    + help_result.stderr
                    + version_result.stdout
                    + version_result.stderr
                    + help_as_value_result.stdout
                    + help_as_value_result.stderr,
                    "help/version output",
                )

    def test_rescue_rejects_wrong_password_and_preserves_existing_destination(self) -> None:
        master = b"Rescue-Rejection-Master-Secret-111!"
        wrong_master = b"Rescue-Wrong-Master-Secret-222!"
        record_secret = b"Rescue-Rejection-Record-Secret-333!"
        marker = b"existing-output-must-remain-byte-exact"

        with tempfile.TemporaryDirectory(prefix="pvault-rescue-reject-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            environment = isolated_environment(root)
            source = root / "source.pvlt"
            recovery = root / "recovery.txt"
            wrong_output = root / "wrong-password-output.pvlt"
            tampered = root / "tampered-source.pvlt"
            tampered_output = root / "tampered-output.pvlt"
            existing = root / "existing-output.pvlt"

            initialize_vault(
                PVAULT,
                source,
                recovery,
                master,
                cwd=REPOSITORY,
                env=environment,
            )
            add_record(
                PVAULT,
                source,
                master,
                record_secret,
                title=b"Rescue Rejection Fixture",
                username=b"rescue-rejection-user",
                cwd=REPOSITORY,
                env=environment,
            )
            recovery_secret = self.recovery_secret(recovery)
            all_secrets = (master, wrong_master, record_secret, recovery_secret)
            source_state = self.snapshot_state(source)

            tampered_bytes = bytearray(source_state[0])
            tampered_bytes[-1] ^= 0x01
            tampered.write_bytes(tampered_bytes)
            tampered.chmod(0o600)
            tampered_output_text = self.run_snapshot_password_authenticated(
                ("rescue", "recover", tampered, "--output", tampered_output),
                master,
                all_secrets,
                environment=environment,
                expected_returncode=3,
            )
            self.assertIn(
                b"authentication or integrity check failed",
                tampered_output_text,
            )
            self.assertFalse(tampered_output.exists())
            self.assert_snapshot_state(source, source_state)

            with PtyProcess(
                [PVAULT, "rescue", "recover", source, "--output", "--help"],
                cwd=root,
                env=environment,
            ) as process:
                self.register_secrets(process, all_secrets)
                process.expect(b"Master password for snapshot: ")
                self.assertFalse(process.echo_enabled())
                self.assert_invocation_clean(process, all_secrets)
                process.send_line(wrong_master)
                help_as_output_text = self.finish_secret_process(
                    process,
                    all_secrets,
                    expected_returncode=3,
                )
            self.assertIn(b"authentication or integrity check failed", help_as_output_text)
            self.assertNotIn(b"Usage: pvault rescue recover", help_as_output_text)
            self.assertFalse((root / "--help").exists())
            self.assert_snapshot_state(source, source_state)

            wrong_output_text = self.run_snapshot_password_authenticated(
                ("rescue", "recover", source, "--output", wrong_output),
                wrong_master,
                all_secrets,
                environment=environment,
                expected_returncode=3,
            )
            self.assertIn(
                b"authentication or integrity check failed",
                wrong_output_text,
            )
            self.assertFalse(wrong_output.exists())
            self.assert_snapshot_state(source, source_state)

            existing.write_bytes(marker)
            existing.chmod(0o600)
            existing_state = self.snapshot_state(existing)
            collision_output = self.run_snapshot_password_authenticated(
                ("rescue", "recover", source, "--output", existing),
                master,
                all_secrets,
                environment=environment,
                expected_returncode=1,
            )
            self.assertIn(b"object already exists", collision_output)
            self.assert_snapshot_state(existing, existing_state)
            self.assertEqual(marker, existing.read_bytes())
            self.assert_snapshot_state(source, source_state)
            for secret in all_secrets:
                self.assert_secret_absent(secret, collision_output, "collision output")

    def test_secret_prompt_signals_restore_echo_and_do_not_commit(self) -> None:
        for signal_number in (
            signal.SIGINT,
            signal.SIGHUP,
            signal.SIGQUIT,
            signal.SIGTERM,
        ):
            with self.subTest(signal=signal.Signals(signal_number).name):
                with tempfile.TemporaryDirectory(prefix="pvault-signal-") as temporary:
                    root = Path(temporary)
                    root.chmod(0o700)
                    environment = isolated_environment(root)
                    vault = root / "vault.pvlt"
                    recovery = root / "recovery.txt"
                    partial_secret = (
                        f"SIGNAL-SECRET-{signal.Signals(signal_number).name}"
                    ).encode("ascii")

                    with PtyProcess(
                        [PVAULT, "--vault", vault, "init", "--recovery-out", recovery],
                        cwd=REPOSITORY,
                        env=environment,
                    ) as process:
                        process.register_secret(partial_secret)
                        process.expect(b"New master password: ")
                        self.assertFalse(process.echo_enabled())
                        self.assertEqual(
                            [], invocation_contains_secret(process, partial_secret)
                        )
                        process.send(partial_secret)
                        process.read_for(0.15)
                        self.assert_secret_absent(partial_secret, process.output, "signal prompt output")
                        process.send_signal(signal_number)
                        returncode = process.wait(5.0)
                        self.assertEqual(-signal_number, returncode, process.safe_output())
                        self.assert_secret_absent(partial_secret, process.output, "signal exit output")
                        self.assertTrue(process.echo_enabled())
                    self.assertFalse(vault.exists())
                    self.assertFalse(recovery.exists())

    def test_internal_picker_signals_restore_echo_after_unlock(self) -> None:
        master = b"Picker-Signal-Master-Secret-123!"
        record_secret = b"Picker-Signal-Record-Secret-456!"
        secrets = (master, record_secret)

        with tempfile.TemporaryDirectory(prefix="pvault-picker-signals-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            environment = isolated_environment(root)
            vault = root / "vault.pvlt"
            recovery = root / "recovery.txt"

            initialize_vault(
                PVAULT,
                vault,
                recovery,
                master,
                cwd=REPOSITORY,
                env=environment,
            )
            add_record(
                PVAULT,
                vault,
                master,
                record_secret,
                title=b"Picker Signal Fixture",
                username=b"picker-signal-user",
                cwd=REPOSITORY,
                env=environment,
            )
            vault_before = vault.read_bytes()

            for signal_number in (
                signal.SIGINT,
                signal.SIGTERM,
                signal.SIGHUP,
                signal.SIGQUIT,
                signal.SIGTSTP,
            ):
                with self.subTest(signal=signal.Signals(signal_number).name):
                    with PtyProcess(
                        [PVAULT, "--vault", vault, "show"],
                        cwd=REPOSITORY,
                        env=environment,
                    ) as process:
                        self.register_secrets(process, secrets)
                        process.expect(b"Master password: ")
                        self.assertFalse(process.echo_enabled())
                        self.assert_invocation_clean(process, secrets)
                        process.send_line(master)
                        process.expect(b"PVault search:")
                        self.assertFalse(process.echo_enabled())
                        ignored = process_signal_ignored(process.pid, signal_number)
                        process.send_signal(signal_number)

                        if signal_number == signal.SIGTSTP:
                            if ignored:
                                process.read_for(0.2)
                                self.assertIsNone(process.returncode)
                                self.assertFalse(process.echo_enabled())
                                process.send_signal(signal.SIGTERM)
                            else:
                                wait_until(
                                    lambda: (
                                        (state := process_state(process.pid)) is None
                                        or state in {"T", "t", "Z"}
                                    ),
                                    5.0,
                                    "internal picker to stop or exit after SIGTSTP",
                                )
                                self.assertTrue(
                                    process.echo_enabled(),
                                    "picker left echo disabled after SIGTSTP cleanup",
                                )
                                if process_state(process.pid) in {"T", "t"}:
                                    process.send_signal(signal.SIGCONT)
                                    process.read_for(0.2)
                                    if process.returncode is None:
                                        process.send_signal(signal.SIGTERM)
                            returncode = process.wait(5.0)
                            self.assertNotEqual(0, returncode, process.safe_output())
                        else:
                            returncode = process.wait(5.0)
                            self.assertNotEqual(
                                0,
                                returncode,
                                process.safe_output(),
                            )

                        self.assert_secret_absent(
                            master,
                            process.output,
                            "picker signal terminal output",
                        )
                        self.assert_secret_absent(
                            record_secret,
                            process.output,
                            "picker signal terminal output",
                        )
                        self.assertTrue(
                            process.echo_enabled(),
                            "picker did not restore echo after signal",
                        )

            self.assertEqual(vault_before, vault.read_bytes())

    def test_stop_signal_restores_echo_before_stop_or_exit(self) -> None:
        partial_secret = b"STOP-SIGNAL-SECRET-MUST-NOT-ECHO"
        with tempfile.TemporaryDirectory(prefix="pvault-stop-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            environment = isolated_environment(root)
            vault = root / "vault.pvlt"
            recovery = root / "recovery.txt"

            with PtyProcess(
                [PVAULT, "--vault", vault, "init", "--recovery-out", recovery],
                cwd=REPOSITORY,
                env=environment,
            ) as process:
                process.register_secret(partial_secret)
                process.expect(b"New master password: ")
                self.assertFalse(process.echo_enabled())
                process.send(partial_secret)
                process.read_for(0.1)
                process.send_signal(signal.SIGTSTP)
                process.read_for(0.4)

                self.assertTrue(process.echo_enabled())
                if process.returncode is None and process_state(process.pid) in {"T", "t"}:
                    process.send_signal(signal.SIGCONT)
                returncode = process.wait(5.0)
                self.assertNotEqual(0, returncode, process.safe_output())
                self.assert_secret_absent(partial_secret, process.output, "stop-signal output")

            self.assertFalse(vault.exists())
            self.assertFalse(recovery.exists())

    def test_missing_controlling_tty_is_explicit_and_noninteractive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pvault-no-tty-") as temporary:
            root = Path(temporary)
            environment = isolated_environment(root)
            vault = root / "vault.pvlt"
            recovery = root / "recovery.txt"
            sentinel = b"NO-TTY-SECRET-MUST-NOT-BE-READ"
            self.assertNotIn(
                sentinel,
                b"\0".join(os.fsencode(value) for value in environment.values()),
            )
            completed = subprocess.run(
                [PVAULT, "--vault", vault, "init", "--recovery-out", recovery],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd=REPOSITORY,
                start_new_session=True,
                timeout=5.0,
                check=False,
            )
            self.assertNotEqual(0, completed.returncode)
            self.assertIn(b"controlling terminal (/dev/tty) is required", completed.stderr)
            self.assertNotIn(sentinel, completed.stdout + completed.stderr)
            self.assertFalse(vault.exists())
            self.assertFalse(recovery.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
