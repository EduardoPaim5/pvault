#!/usr/bin/env python3
"""Disposable end-to-end restore drill using synthetic credentials only."""

from __future__ import annotations

import os
import stat
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Mapping, Sequence

from pty_harness import (
    PtyProcess,
    add_record,
    initialize_vault,
    invocation_contains_secret,
    isolated_environment,
)


REPOSITORY = Path(__file__).resolve().parents[2]
BUILD_DIRECTORY = Path(
    os.environ.get("PVAULT_BUILD_DIR", str(REPOSITORY / "build" / "restore-drill"))
).resolve()
PVAULT = BUILD_DIRECTORY / "pvault"

# Public, synthetic canaries. These values must never be reused as real secrets.
MASTER_PASSWORD = b"PVault-RESTORE-DRILL-ONLY-Master-2026!"
RETAINED_PASSWORD = b"PVault-RESTORE-DRILL-ONLY-Retained-Secret!"
MUTATION_PASSWORD = b"PVault-RESTORE-DRILL-ONLY-Mutation-Secret!"
RETAINED_TITLE = b"PVault Synthetic Retained Record"
RETAINED_USERNAME = b"synthetic-retained-user"
MUTATION_TITLE = b"PVault Synthetic Post-Backup Mutation"
MUTATION_USERNAME = b"synthetic-mutation-user"

SECRET_CANARIES = (
    MASTER_PASSWORD,
    RETAINED_PASSWORD,
    MUTATION_PASSWORD,
)
PLAINTEXT_CANARIES = SECRET_CANARIES + (
    RETAINED_TITLE,
    RETAINED_USERNAME,
    MUTATION_TITLE,
    MUTATION_USERNAME,
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def digest(path: Path) -> bytes:
    return sha256(path.read_bytes()).digest()


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def register_secrets(process: PtyProcess, secrets: Sequence[bytes]) -> None:
    for secret in secrets:
        process.register_secret(secret)


def assert_invocation_clean(process: PtyProcess, secrets: Sequence[bytes]) -> None:
    for secret in secrets:
        violations = invocation_contains_secret(process, secret)
        require(not violations, f"secret appeared in process invocation: {violations}")


def finish_process(
    process: PtyProcess,
    secrets: Sequence[bytes],
    *,
    timeout: float = 20.0,
) -> bytes:
    returncode = process.wait(timeout)
    output = bytes(process.output)
    for secret in secrets:
        require(secret not in output, "secret appeared in terminal output")
    require(process.echo_enabled(), "terminal echo was not restored")
    require(returncode == 0, f"command failed ({returncode}): {process.safe_output()!r}")
    return output


def run_password_command(
    arguments: Sequence[str | os.PathLike[str]],
    prompt: bytes,
    password: bytes,
    *,
    environment: Mapping[str, str],
    secrets: Sequence[bytes] = SECRET_CANARIES,
) -> bytes:
    with PtyProcess([PVAULT, *arguments], cwd=REPOSITORY, env=environment) as process:
        register_secrets(process, secrets)
        process.expect(prompt)
        require(not process.echo_enabled(), f"echo was enabled at {prompt!r}")
        assert_invocation_clean(process, secrets)
        process.send_line(password)
        return finish_process(process, secrets)


def run_restore(
    target: Path,
    snapshot: Path,
    password: bytes,
    *,
    environment: Mapping[str, str],
) -> bytes:
    with PtyProcess(
        [PVAULT, "--vault", target, "restore", snapshot],
        cwd=REPOSITORY,
        env=environment,
    ) as process:
        register_secrets(process, SECRET_CANARIES)
        process.expect(b"Master password for backup: ")
        require(not process.echo_enabled(), "echo was enabled at restore password prompt")
        assert_invocation_clean(process, SECRET_CANARIES)
        process.send_line(password)
        process.expect(b"Restore this authenticated backup? [y/N]: ")
        require(process.echo_enabled(), "echo was disabled at restore confirmation")
        process.send_line(b"y")
        return finish_process(process, SECRET_CANARIES)


def run_without_input(
    arguments: Sequence[str | os.PathLike[str]],
    *,
    environment: Mapping[str, str],
    secrets: Sequence[bytes],
) -> bytes:
    with PtyProcess([PVAULT, *arguments], cwd=REPOSITORY, env=environment) as process:
        register_secrets(process, secrets)
        assert_invocation_clean(process, secrets)
        return finish_process(process, secrets)


def recovery_text(path: Path) -> bytes:
    for line in path.read_bytes().splitlines():
        if line.startswith(b"PV1R-"):
            return line
    raise AssertionError("recovery file did not contain a PV1R recovery value")


def assert_encrypted_files_have_no_plaintext(paths: Sequence[Path]) -> None:
    for path in paths:
        data = path.read_bytes()
        for canary in PLAINTEXT_CANARIES:
            require(canary not in data, f"plaintext canary appeared in encrypted file {path}")


def run_drill() -> None:
    require(PVAULT.is_file() and os.access(PVAULT, os.X_OK), f"missing executable {PVAULT}")

    with tempfile.TemporaryDirectory(prefix="pvault-restore-drill-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        require(mode(root) == 0o700, "drill root is not mode 0700")
        environment = isolated_environment(root)

        active = root / "active.pvlt"
        recovery = root / "recovery.txt"
        backup = root / "authenticated-backup.pvlt"
        recovered = root / "recovered-read-only.pvlt"
        rollback_copy = root / "rollback-read-only.pvlt"
        restored = root / "isolated-restored.pvlt"
        outputs: list[bytes] = []

        outputs.append(
            initialize_vault(
                PVAULT,
                active,
                recovery,
                MASTER_PASSWORD,
                cwd=REPOSITORY,
                env=environment,
            )
        )
        outputs.append(
            add_record(
                PVAULT,
                active,
                MASTER_PASSWORD,
                RETAINED_PASSWORD,
                title=RETAINED_TITLE,
                username=RETAINED_USERNAME,
                cwd=REPOSITORY,
                env=environment,
            )
        )
        require(mode(active) == 0o600, "active vault is not mode 0600")
        require(mode(recovery) == 0o600, "recovery file is not mode 0600")

        outputs.append(
            run_password_command(
                ["--vault", active, "backup", "--output", backup],
                b"Master password: ",
                MASTER_PASSWORD,
                environment=environment,
            )
        )
        require(mode(backup) == 0o600, "manual backup is not mode 0600")
        backup_digest = digest(backup)

        outputs.append(
            add_record(
                PVAULT,
                active,
                MASTER_PASSWORD,
                MUTATION_PASSWORD,
                title=MUTATION_TITLE,
                username=MUTATION_USERNAME,
                cwd=REPOSITORY,
                env=environment,
            )
        )
        mutated_active_digest = digest(active)
        require(mutated_active_digest != backup_digest, "synthetic mutation did not change active bytes")

        outputs.append(
            run_password_command(
                ["rescue", "recover", backup, "--output", recovered],
                b"Master password for snapshot: ",
                MASTER_PASSWORD,
                environment=environment,
            )
        )
        require(digest(active) == mutated_active_digest, "rescue recover modified the active vault")
        require(digest(backup) == backup_digest, "rescue recover modified the backup")
        require(digest(recovered) == backup_digest, "recovery copy is not byte-exact")
        require(mode(recovered) == 0o400, "recovery copy is not pinned mode 0400")

        verify_password_output = run_password_command(
            ["rescue", "verify", recovered],
            b"Master password for snapshot: ",
            MASTER_PASSWORD,
            environment=environment,
        )
        outputs.append(verify_password_output)
        require(b"Authenticated snapshot" in verify_password_output, "password verify did not authenticate")
        require(b"Generation: 2" in verify_password_output, "backup generation was not the expected value 2")
        require(b"Record count: 1" in verify_password_output, "backup record count was not one")

        encoded_recovery = recovery_text(recovery)
        verify_recovery_output = run_without_input(
            ["rescue", "verify", recovered, "--recovery", recovery],
            environment=environment,
            secrets=SECRET_CANARIES + (encoded_recovery,),
        )
        outputs.append(verify_recovery_output)
        require(b"Authenticated snapshot" in verify_recovery_output, "recovery verify did not authenticate")
        require(b"Generation: 2" in verify_recovery_output, "recovery verify reported wrong generation")

        outputs.append(
            run_password_command(
                ["rollback", backup, "--output", rollback_copy],
                b"Master password for snapshot: ",
                MASTER_PASSWORD,
                environment=environment,
            )
        )
        require(digest(active) == mutated_active_digest, "rollback copy modified the active vault")
        require(digest(backup) == backup_digest, "rollback copy modified the backup")
        require(digest(rollback_copy) == backup_digest, "rollback copy is not byte-exact")
        require(mode(rollback_copy) == 0o400, "rollback copy is not pinned mode 0400")

        rollback_password_verify = run_password_command(
            ["rescue", "verify", rollback_copy],
            b"Master password for snapshot: ",
            MASTER_PASSWORD,
            environment=environment,
        )
        outputs.append(rollback_password_verify)
        require(
            b"Generation: 2" in rollback_password_verify and b"Record count: 1" in rollback_password_verify,
            "password verification of rollback copy reported unexpected state",
        )
        rollback_recovery_verify = run_without_input(
            ["rescue", "verify", rollback_copy, "--recovery", recovery],
            environment=environment,
            secrets=SECRET_CANARIES + (encoded_recovery,),
        )
        outputs.append(rollback_recovery_verify)
        require(
            b"Generation: 2" in rollback_recovery_verify and b"Record count: 1" in rollback_recovery_verify,
            "recovery verification of rollback copy reported unexpected state",
        )

        # First materialize the authenticated snapshot under a separate active path.
        outputs.append(run_restore(restored, recovered, MASTER_PASSWORD, environment=environment))
        require(digest(active) == mutated_active_digest, "isolated restore modified the active vault")
        require(digest(backup) == backup_digest, "isolated restore modified the backup")
        require(digest(recovered) == backup_digest, "isolated restore modified the recovery copy")
        require(digest(restored) == backup_digest, "isolated restore was not byte-exact")
        require(mode(restored) == 0o600, "isolated restored vault is not mode 0600")

        # Mutate only the isolated target, then restore over it. The restore must
        # preserve this exact intermediate state as a pre-restore snapshot.
        outputs.append(
            add_record(
                PVAULT,
                restored,
                MASTER_PASSWORD,
                MUTATION_PASSWORD,
                title=MUTATION_TITLE,
                username=MUTATION_USERNAME,
                cwd=REPOSITORY,
                env=environment,
            )
        )
        target_mutated_bytes = restored.read_bytes()
        require(
            sha256(target_mutated_bytes).digest() != backup_digest,
            "isolated target mutation did not change its bytes",
        )
        require(digest(active) == mutated_active_digest, "isolated target mutation modified active")
        mutated_target_list = run_password_command(
            ["--vault", restored, "list"],
            b"Master password: ",
            MASTER_PASSWORD,
            environment=environment,
        )
        outputs.append(mutated_target_list)
        require(RETAINED_TITLE in mutated_target_list, "retained record disappeared before restore")
        require(MUTATION_TITLE in mutated_target_list, "isolated target mutation is absent")
        require(b"2 records" in mutated_target_list, "isolated target does not contain two records")

        backup_directory = root / "backups"
        pre_restore_before = set(backup_directory.glob("pre-restore-*.pvlt"))
        outputs.append(run_restore(restored, backup, MASTER_PASSWORD, environment=environment))
        pre_restore_after = set(backup_directory.glob("pre-restore-*.pvlt"))
        created_pre_restore = pre_restore_after - pre_restore_before
        require(len(created_pre_restore) == 1, "restore did not create exactly one pre-restore snapshot")
        pre_restore = created_pre_restore.pop()
        require(pre_restore.read_bytes() == target_mutated_bytes, "pre-restore is not byte-exact")
        require(mode(pre_restore) == 0o600, "pre-restore snapshot is not mode 0600")

        pre_restore_password_verify = run_password_command(
            ["rescue", "verify", pre_restore],
            b"Master password for snapshot: ",
            MASTER_PASSWORD,
            environment=environment,
        )
        outputs.append(pre_restore_password_verify)
        require(
            b"Generation: 3" in pre_restore_password_verify and b"Record count: 2" in pre_restore_password_verify,
            "password verification of pre-restore reported unexpected state",
        )
        pre_restore_recovery_verify = run_without_input(
            ["rescue", "verify", pre_restore, "--recovery", recovery],
            environment=environment,
            secrets=SECRET_CANARIES + (encoded_recovery,),
        )
        outputs.append(pre_restore_recovery_verify)
        require(
            b"Generation: 3" in pre_restore_recovery_verify and b"Record count: 2" in pre_restore_recovery_verify,
            "recovery verification of pre-restore reported unexpected state",
        )

        require(digest(active) == mutated_active_digest, "restore over isolated target modified active")
        require(restored.read_bytes() == backup.read_bytes(), "final isolated target differs from backup")
        require(mode(restored) == 0o600, "final isolated target is not mode 0600")
        restored_list = run_password_command(
            ["--vault", restored, "list"],
            b"Master password: ",
            MASTER_PASSWORD,
            environment=environment,
        )
        outputs.append(restored_list)
        require(RETAINED_TITLE in restored_list, "retained record is absent after restore")
        require(MUTATION_TITLE not in restored_list, "post-backup mutation survived rollback")
        require(b"1 record" in restored_list, "restored vault does not contain exactly one record")

        restored_verify = run_password_command(
            ["rescue", "verify", restored],
            b"Master password for snapshot: ",
            MASTER_PASSWORD,
            environment=environment,
        )
        outputs.append(restored_verify)
        require(b"Generation: 2" in restored_verify, "restored generation was not preserved")
        require(b"Record count: 1" in restored_verify, "restored record count was not preserved")

        assert_encrypted_files_have_no_plaintext(
            (active, backup, recovered, rollback_copy, pre_restore, restored)
        )
        for output in outputs:
            for secret in SECRET_CANARIES + (encoded_recovery,):
                require(secret not in output, "secret appeared in captured command output")

        require(mode(root) == 0o700, "drill root permissions changed")
        print("restore drill: PASS (synthetic data only; active vault remained unchanged)")


def main() -> int:
    try:
        run_drill()
    except (AssertionError, OSError, TimeoutError) as error:
        print(f"restore drill: FAIL: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
