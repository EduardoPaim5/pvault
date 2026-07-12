from __future__ import annotations

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
    add_record,
    initialize_vault,
    invocation_contains_secret,
    isolated_environment,
    process_state,
)


REPOSITORY = Path(__file__).resolve().parents[2]
BUILD_DIRECTORY = Path(
    os.environ.get("PVAULT_BUILD_DIR", str(REPOSITORY / "build" / "debug"))
).resolve()
PVAULT = BUILD_DIRECTORY / "pvault"


class CliPtyIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not PVAULT.is_file():
            raise unittest.SkipTest(f"build the CLI first: missing {PVAULT}")

    def assert_secret_absent(self, secret: bytes, data: bytes | bytearray, location: str) -> None:
        if secret in data:
            self.fail(f"secret appeared in {location}")

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
            return self.finish_secret_process(
                process,
                secrets,
                expected_returncode=expected_returncode,
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
            return self.finish_secret_process(process, secrets)

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
            vault = root / "vault.pvlt"
            recovery = root / "recovery.txt"

            init_output = initialize_vault(
                PVAULT,
                vault,
                recovery,
                master,
                cwd=REPOSITORY,
                env=environment,
            )
            self.assertIn(b"Vault created at", init_output)
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
            self.assertIn(b"Added ", add_output)

            with PtyProcess(
                [PVAULT, "--vault", vault, "show", "PTY"],
                cwd=REPOSITORY,
                env=environment,
            ) as process:
                process.register_secret(master)
                process.register_secret(record_secret)
                process.expect(b"Master password: ")
                self.assertFalse(process.echo_enabled())
                self.assertEqual([], invocation_contains_secret(process, master))
                process.send_line(master)
                self.assertEqual(0, process.wait(15.0), process.safe_output())
                output = bytes(process.output)
                self.assertIn(b"Title: PTY Account", output)
                self.assertIn(b"Username: pty-user", output)
                self.assertIn(b"Password: <secret>", output)
                self.assert_secret_absent(master, output, "show output")
                self.assert_secret_absent(record_secret, output, "show output")
                self.assertTrue(process.echo_enabled())

            vault_bytes = vault.read_bytes()
            self.assert_secret_absent(master, vault_bytes, "encrypted vault bytes")
            self.assert_secret_absent(record_secret, vault_bytes, "encrypted vault bytes")
            self.assertEqual(0o600, stat.S_IMODE(vault.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(recovery.stat().st_mode))

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
            rotated_recovery = root / "recovery-rotated.txt"

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
                ("show", "Rotation Fixture"),
                rotated_master,
                all_secrets,
                environment=environment,
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
                ("show", "Rotation Fixture"),
                recovered_master,
                all_secrets,
                environment=environment,
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
            backup = root / "manual-backup.pvlt"

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
            self.assertIn(b"Vault restored from", restore_output)
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
                ("show", "Retained Fixture"),
                master,
                all_secrets,
                environment=environment,
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
