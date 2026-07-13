#!/usr/bin/env python3
"""Create and exercise a nonce-bound, synthetic PVault restore fixture.

This helper is intentionally limited to public synthetic canaries.  It never
accepts a password, recovery value, title, username, or record field from its
caller.  Caller-controlled test fields are deterministically derived from the
request nonce; the recovery value is generated internally by a fresh synthetic
vault.  None of these values are suitable for real use.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, NoReturn, Sequence


INTEGRATION_DIRECTORY = Path(__file__).resolve().parents[1] / "integration"
sys.path.insert(0, str(INTEGRATION_DIRECTORY))

from pty_harness import (  # noqa: E402
    PtyProcess,
    add_record,
    initialize_vault,
    invocation_contains_secret,
    isolated_environment,
)


SCHEMA_VERSION = 1
FIXTURE_SCHEMA = "pvault.external-restore.fixture"
RESULT_SCHEMA = "pvault.external-restore.exercise-result"
SUMMARY_NAME = "fixture-summary.json"
ACTIVE_NAME = "active-mutated.pvlt"
BACKUP_NAME = "backup.pvlt"
RECOVERY_NAME = "recovery.pvault-recovery"
MASTER_PASSWORD_NAME = "master-password.bin"
PRE_RESTORE_EVIDENCE_NAME = "pre-restore.pvlt"
FINAL_RESTORED_EVIDENCE_NAME = "final-restored.pvlt"
PAYLOAD_NAMES = (
    ACTIVE_NAME,
    BACKUP_NAME,
    MASTER_PASSWORD_NAME,
    RECOVERY_NAME,
)
FIXTURE_NAMES = frozenset((*PAYLOAD_NAMES, SUMMARY_NAME))
NONCE_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")
LOWER_HEX_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
MAX_SUMMARY_BYTES = 64 * 1024
MAX_VAULT_BYTES = 128 * 1024 * 1024
MAX_RECOVERY_BYTES = 64 * 1024
MAX_MASTER_PASSWORD_BYTES = 256
FILE_LIMITS = {
    ACTIVE_NAME: MAX_VAULT_BYTES,
    BACKUP_NAME: MAX_VAULT_BYTES,
    MASTER_PASSWORD_NAME: MAX_MASTER_PASSWORD_BYTES,
    RECOVERY_NAME: MAX_RECOVERY_BYTES,
    SUMMARY_NAME: MAX_SUMMARY_BYTES,
}
EXPECTED_SEMANTICS = {
    "active_mutated": {"generation": 3, "record_count": 2},
    "backup": {"generation": 2, "record_count": 1},
}
EXPECTED_CHECK_NAMES = frozenset(
    {
        "active_mutated_password_authenticated",
        "active_mutated_recovery_authenticated",
        "active_mutated_semantics",
        "backup_password_authenticated",
        "backup_recovery_authenticated",
        "backup_semantics",
        "encrypted_inputs_contain_no_plaintext",
        "final_restored_byte_exact",
        "final_restored_semantics",
        "fixture_inputs_unchanged",
        "pre_restore_byte_exact",
        "pre_restore_semantics",
        "restore_completed",
    }
)


class FixtureError(RuntimeError):
    """A fail-closed fixture creation or exercise error."""


@dataclass(frozen=True)
class SyntheticMaterial:
    """Nonce-derived public test values that must never be used as credentials."""

    master_password: bytes
    retained_password: bytes
    mutation_password: bytes
    retained_title: bytes
    retained_username: bytes
    mutation_title: bytes
    mutation_username: bytes

    @property
    def secret_canaries(self) -> tuple[bytes, ...]:
        return (
            self.master_password,
            self.retained_password,
            self.mutation_password,
        )

    @property
    def plaintext_canaries(self) -> tuple[bytes, ...]:
        return (
            *self.secret_canaries,
            self.retained_title,
            self.retained_username,
            self.mutation_title,
            self.mutation_username,
        )


@dataclass(frozen=True)
class ValidatedFixture:
    root: Path
    nonce_hex: str
    summary_bytes: bytes
    summary: dict[str, object]
    files: dict[str, bytes]
    material: SyntheticMaterial
    recovery_value: bytes


def fail(message: str) -> NoReturn:
    raise FixtureError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise FixtureError("cannot serialize canonical JSON") from error
    return (rendered + "\n").encode("ascii")


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> NoReturn:
    fail(f"non-finite JSON value is forbidden: {value}")


def parse_canonical_json(data: bytes) -> dict[str, object]:
    require(len(data) <= MAX_SUMMARY_BYTES, "canonical JSON exceeds its size limit")
    try:
        text = data.decode("ascii", "strict")
        parsed = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise FixtureError("invalid canonical JSON") from error
    require(type(parsed) is dict, "canonical JSON root must be an object")
    require(canonical_json_bytes(parsed) == data, "JSON is not in canonical form")
    return parsed


def require_exact_keys(value: object, expected: set[str] | frozenset[str], label: str) -> dict[str, object]:
    require(type(value) is dict, f"{label} must be an object")
    mapping = value
    require(set(mapping) == set(expected), f"{label} contains missing or unknown fields")
    return mapping


def require_unsigned(value: object, label: str, *, maximum: int = (1 << 53) - 1) -> int:
    require(type(value) is int, f"{label} must be an integer")
    integer = value
    require(0 <= integer <= maximum, f"{label} is outside its supported range")
    return integer


def require_lower_hex(value: object, label: str) -> str:
    require(type(value) is str, f"{label} must be a string")
    require(LOWER_HEX_PATTERN.fullmatch(value) is not None, f"{label} must be lowercase SHA-256 hex")
    return value


def normalize_nonce(value: str) -> str:
    require(NONCE_PATTERN.fullmatch(value) is not None, "nonce must be exactly 64 hexadecimal characters")
    return value.lower()


def derive_token(nonce: bytes, label: bytes, length: int) -> str:
    digest = hashlib.sha256(
        b"pvault-external-restore-synthetic-v1\0" + label + b"\0" + nonce
    ).hexdigest()
    return digest[:length]


def synthetic_material(nonce_hex: str) -> SyntheticMaterial:
    nonce = bytes.fromhex(nonce_hex)
    master = derive_token(nonce, b"master-password", 32)
    retained = derive_token(nonce, b"retained-password", 32)
    mutation = derive_token(nonce, b"mutation-password", 32)
    retained_record = derive_token(nonce, b"retained-record", 16)
    mutation_record = derive_token(nonce, b"mutation-record", 16)
    return SyntheticMaterial(
        master_password=f"PVault-EXTERNAL-DRILL-ONLY-Master-{master}!".encode("ascii"),
        retained_password=f"PVault-EXTERNAL-DRILL-ONLY-Retained-{retained}!".encode("ascii"),
        mutation_password=f"PVault-EXTERNAL-DRILL-ONLY-Mutation-{mutation}!".encode("ascii"),
        retained_title=f"PVault Synthetic External Retained {retained_record}".encode("ascii"),
        retained_username=f"synthetic-retained-{retained_record}".encode("ascii"),
        mutation_title=f"PVault Synthetic External Mutation {mutation_record}".encode("ascii"),
        mutation_username=f"synthetic-mutation-{mutation_record}".encode("ascii"),
    )


def validate_pvault(value: str) -> Path:
    candidate = Path(value)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise FixtureError("cannot resolve the PVault executable") from error
    require(resolved.is_file(), "PVault executable is not a regular file")
    require(os.access(resolved, os.X_OK), "PVault executable is not executable")
    return resolved


def absolute_unresolved(value: str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(value)))


def lstat_path(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise FixtureError(f"cannot inspect path: {path}") from error


def require_private_directory(path: Path, label: str) -> None:
    metadata = lstat_path(path)
    require(stat.S_ISDIR(metadata.st_mode), f"{label} is not a directory")
    require(metadata.st_uid == os.geteuid(), f"{label} is not owned by the current user")
    require(stat.S_IMODE(metadata.st_mode) == 0o700, f"{label} must have mode 0700")


def read_private_file(path: Path, *, maximum: int, label: str) -> bytes:
    before = lstat_path(path)
    require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
    require(before.st_uid == os.geteuid(), f"{label} is not owned by the current user")
    require(before.st_nlink == 1, f"{label} must have exactly one hard link")
    require(stat.S_IMODE(before.st_mode) == 0o600, f"{label} must have mode 0600")
    require(0 < before.st_size <= maximum, f"{label} has an invalid size")

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FixtureError(f"cannot open {label}") from error
    try:
        opened = os.fstat(descriptor)
        require(
            (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
            f"{label} changed while it was opened",
        )
        require(stat.S_ISREG(opened.st_mode), f"opened {label} is not regular")
        require(opened.st_uid == os.geteuid(), f"opened {label} owner changed")
        require(opened.st_nlink == 1, f"opened {label} link count changed")
        require(stat.S_IMODE(opened.st_mode) == 0o600, f"opened {label} mode changed")
        require(0 < opened.st_size <= maximum, f"opened {label} size is invalid")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        require(len(data) <= maximum, f"{label} exceeds its size limit")
        require(len(data) == opened.st_size, f"{label} changed while it was read")
        return data
    finally:
        os.close(descriptor)


def write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        require(written > 0, "short write while publishing a fixture artifact")
        view = view[written:]


def write_exclusive(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        raise FixtureError(f"cannot create output without replacement: {path}") from error
    try:
        os.fchmod(descriptor, mode)
        write_all(descriptor, data)
        os.fsync(descriptor)
    except BaseException:
        try:
            os.close(descriptor)
        finally:
            try:
                path.unlink()
            except OSError:
                pass
        raise
    os.close(descriptor)


def fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def file_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def recovery_value(contents: bytes) -> bytes:
    values = [line for line in contents.splitlines() if line.startswith(b"PV1R-")]
    require(len(values) == 1, "recovery file must contain exactly one PV1R value")
    return values[0]


def register_secrets(process: PtyProcess, secrets: Sequence[bytes]) -> None:
    for secret in secrets:
        process.register_secret(secret)


def assert_invocation_clean(process: PtyProcess, secrets: Sequence[bytes]) -> None:
    for secret in secrets:
        violations = invocation_contains_secret(process, secret)
        require(not violations, f"synthetic secret appeared in process invocation: {violations}")


def finish_process(
    process: PtyProcess,
    secrets: Sequence[bytes],
    *,
    timeout: float = 20.0,
) -> bytes:
    returncode = process.wait(timeout)
    output = bytes(process.output)
    for secret in secrets:
        require(secret not in output, "synthetic secret appeared in terminal output")
    require(process.echo_enabled(), "terminal echo was not restored")
    require(returncode == 0, f"PVault command failed ({returncode}): {process.safe_output()!r}")
    return output


def run_password_command(
    pvault: Path,
    arguments: Sequence[str | os.PathLike[str]],
    prompt: bytes,
    password: bytes,
    *,
    cwd: Path,
    environment: Mapping[str, str],
    secrets: Sequence[bytes],
) -> bytes:
    with PtyProcess([pvault, *arguments], cwd=cwd, env=environment) as process:
        register_secrets(process, secrets)
        process.expect(prompt)
        require(not process.echo_enabled(), f"echo was enabled at prompt {prompt!r}")
        assert_invocation_clean(process, secrets)
        process.send_line(password)
        return finish_process(process, secrets)


def run_without_input(
    pvault: Path,
    arguments: Sequence[str | os.PathLike[str]],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    secrets: Sequence[bytes],
) -> bytes:
    with PtyProcess([pvault, *arguments], cwd=cwd, env=environment) as process:
        register_secrets(process, secrets)
        assert_invocation_clean(process, secrets)
        return finish_process(process, secrets)


def run_restore(
    pvault: Path,
    target: Path,
    snapshot: Path,
    password: bytes,
    *,
    cwd: Path,
    environment: Mapping[str, str],
    secrets: Sequence[bytes],
) -> bytes:
    with PtyProcess(
        [pvault, "--vault", target, "restore", snapshot],
        cwd=cwd,
        env=environment,
    ) as process:
        register_secrets(process, secrets)
        process.expect(b"Master password for backup: ")
        require(not process.echo_enabled(), "echo was enabled at restore password prompt")
        assert_invocation_clean(process, secrets)
        process.send_line(password)
        process.expect(b"Restore this authenticated backup? [y/N]: ")
        require(process.echo_enabled(), "echo was disabled at restore confirmation")
        process.send_line(b"y")
        return finish_process(process, secrets)


def assert_semantics(output: bytes, *, generation: int, record_count: int, label: str) -> None:
    require(b"Authenticated snapshot" in output, f"{label} did not authenticate")
    require(
        f"Generation: {generation}".encode("ascii") in output,
        f"{label} reported the wrong generation",
    )
    require(
        f"Record count: {record_count}".encode("ascii") in output,
        f"{label} reported the wrong record count",
    )


def verify_snapshot_password(
    pvault: Path,
    snapshot: Path,
    material: SyntheticMaterial,
    recovery: bytes,
    *,
    cwd: Path,
    environment: Mapping[str, str],
    generation: int,
    record_count: int,
    label: str,
) -> None:
    secrets = (*material.secret_canaries, recovery)
    output = run_password_command(
        pvault,
        ["rescue", "verify", snapshot],
        b"Master password for snapshot: ",
        material.master_password,
        cwd=cwd,
        environment=environment,
        secrets=secrets,
    )
    assert_semantics(output, generation=generation, record_count=record_count, label=label)


def verify_snapshot_recovery(
    pvault: Path,
    snapshot: Path,
    recovery_path: Path,
    material: SyntheticMaterial,
    recovery: bytes,
    *,
    cwd: Path,
    environment: Mapping[str, str],
    generation: int,
    record_count: int,
    label: str,
) -> None:
    secrets = (*material.secret_canaries, recovery)
    output = run_without_input(
        pvault,
        ["rescue", "verify", snapshot, "--recovery", recovery_path],
        cwd=cwd,
        environment=environment,
        secrets=secrets,
    )
    assert_semantics(output, generation=generation, record_count=record_count, label=label)


def assert_list_semantics(
    output: bytes,
    material: SyntheticMaterial,
    *,
    mutated: bool,
) -> None:
    require(material.retained_title in output, "retained synthetic record is absent")
    if mutated:
        require(material.mutation_title in output, "synthetic mutation is absent")
        require(b"2 records" in output, "mutated vault does not contain two records")
    else:
        require(material.mutation_title not in output, "synthetic mutation survived restore")
        require(b"1 record" in output, "restored vault does not contain one record")


def list_vault(
    pvault: Path,
    vault: Path,
    material: SyntheticMaterial,
    recovery: bytes,
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> bytes:
    return run_password_command(
        pvault,
        ["--vault", vault, "list"],
        b"Master password: ",
        material.master_password,
        cwd=cwd,
        environment=environment,
        secrets=(*material.secret_canaries, recovery),
    )


def assert_no_plaintext(encrypted: Sequence[bytes], canaries: Sequence[bytes]) -> None:
    for contents in encrypted:
        for canary in canaries:
            require(canary not in contents, "plaintext synthetic canary appeared in encrypted bytes")


def manifest_entry(name: str, contents: bytes) -> dict[str, object]:
    return {
        "mode": "0600",
        "name": name,
        "sha256": sha256_hex(contents),
        "size": len(contents),
    }


def fixture_summary(nonce_hex: str, files: Mapping[str, bytes]) -> dict[str, object]:
    return {
        "files": [manifest_entry(name, files[name]) for name in sorted(PAYLOAD_NAMES)],
        "nonce_hex": nonce_hex,
        "schema": FIXTURE_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "semantics": EXPECTED_SEMANTICS,
        "synthetic_only": True,
    }


def publish_fixture(output: Path, files: Mapping[str, bytes], summary_bytes: bytes) -> None:
    require(not os.path.lexists(output), "fixture output already exists")
    try:
        output.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError as error:
        raise FixtureError("cannot create fixture output directory without replacement") from error

    published: list[Path] = []
    try:
        os.chmod(output, 0o700)
        for name in PAYLOAD_NAMES:
            destination = output / name
            write_exclusive(destination, files[name])
            published.append(destination)
        summary_path = output / SUMMARY_NAME
        write_exclusive(summary_path, summary_bytes)
        published.append(summary_path)
        fsync_directory(output)
        fsync_directory(output.parent)
    except BaseException:
        for path in reversed(published):
            try:
                path.unlink()
            except OSError:
                pass
        try:
            output.rmdir()
        except OSError:
            pass
        raise


def remove_published_evidence(evidence_directory: Path) -> None:
    for name in (PRE_RESTORE_EVIDENCE_NAME, FINAL_RESTORED_EVIDENCE_NAME):
        try:
            (evidence_directory / name).unlink()
        except OSError:
            pass
    try:
        evidence_directory.rmdir()
    except OSError:
        pass


def publish_evidence(
    evidence_directory: Path,
    *,
    pre_restore: bytes,
    final_restored: bytes,
) -> None:
    require(not os.path.lexists(evidence_directory), "evidence directory already exists")
    try:
        evidence_directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError as error:
        raise FixtureError("cannot create evidence directory without replacement") from error
    try:
        os.chmod(evidence_directory, 0o700)
        write_exclusive(evidence_directory / PRE_RESTORE_EVIDENCE_NAME, pre_restore)
        write_exclusive(evidence_directory / FINAL_RESTORED_EVIDENCE_NAME, final_restored)
        fsync_directory(evidence_directory)
        fsync_directory(evidence_directory.parent)
    except BaseException:
        remove_published_evidence(evidence_directory)
        raise


def export_fixture(pvault: Path, output: Path, nonce_hex: str) -> None:
    material = synthetic_material(nonce_hex)
    require(output.parent.is_dir(), "fixture output parent does not exist")
    require(not os.path.lexists(output), "fixture output already exists")

    with tempfile.TemporaryDirectory(prefix="pvault-external-fixture-export-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        environment = isolated_environment(root / "runtime")
        active = root / "active.pvlt"
        recovery_path = root / RECOVERY_NAME
        backup = root / BACKUP_NAME
        outputs: list[bytes] = []

        outputs.append(
            initialize_vault(
                pvault,
                active,
                recovery_path,
                material.master_password,
                cwd=root,
                env=environment,
            )
        )
        outputs.append(
            add_record(
                pvault,
                active,
                material.master_password,
                material.retained_password,
                title=material.retained_title,
                username=material.retained_username,
                cwd=root,
                env=environment,
            )
        )
        outputs.append(
            run_password_command(
                pvault,
                ["--vault", active, "backup", "--output", backup],
                b"Master password: ",
                material.master_password,
                cwd=root,
                environment=environment,
                secrets=material.secret_canaries,
            )
        )
        outputs.append(
            add_record(
                pvault,
                active,
                material.master_password,
                material.mutation_password,
                title=material.mutation_title,
                username=material.mutation_username,
                cwd=root,
                env=environment,
            )
        )

        require(file_mode(active) == 0o600, "mutated active vault is not mode 0600")
        require(file_mode(backup) == 0o600, "backup is not mode 0600")
        require(file_mode(recovery_path) == 0o600, "recovery file is not mode 0600")
        active_bytes = active.read_bytes()
        backup_bytes = backup.read_bytes()
        recovery_bytes = recovery_path.read_bytes()
        encoded_recovery = recovery_value(recovery_bytes)
        secrets = (*material.secret_canaries, encoded_recovery)

        verify_snapshot_password(
            pvault,
            backup,
            material,
            encoded_recovery,
            cwd=root,
            environment=environment,
            generation=2,
            record_count=1,
            label="exported backup password verification",
        )
        verify_snapshot_recovery(
            pvault,
            backup,
            recovery_path,
            material,
            encoded_recovery,
            cwd=root,
            environment=environment,
            generation=2,
            record_count=1,
            label="exported backup recovery verification",
        )
        verify_snapshot_password(
            pvault,
            active,
            material,
            encoded_recovery,
            cwd=root,
            environment=environment,
            generation=3,
            record_count=2,
            label="exported mutated vault password verification",
        )
        verify_snapshot_recovery(
            pvault,
            active,
            recovery_path,
            material,
            encoded_recovery,
            cwd=root,
            environment=environment,
            generation=3,
            record_count=2,
            label="exported mutated vault recovery verification",
        )
        active_list = list_vault(
            pvault,
            active,
            material,
            encoded_recovery,
            cwd=root,
            environment=environment,
        )
        assert_list_semantics(active_list, material, mutated=True)

        assert_no_plaintext(
            (active_bytes, backup_bytes),
            (*material.plaintext_canaries, encoded_recovery),
        )
        for captured in outputs:
            for secret in secrets:
                require(secret not in captured, "synthetic secret appeared in captured output")

        files = {
            ACTIVE_NAME: active_bytes,
            BACKUP_NAME: backup_bytes,
            MASTER_PASSWORD_NAME: material.master_password,
            RECOVERY_NAME: recovery_bytes,
        }
        summary_bytes = canonical_json_bytes(fixture_summary(nonce_hex, files))
        publish_fixture(output, files, summary_bytes)

    print(f"external restore fixture export: PASS ({output}; synthetic data only)")


def validate_manifest_entry(value: object, expected_name: str) -> dict[str, object]:
    entry = require_exact_keys(value, {"mode", "name", "sha256", "size"}, "fixture file entry")
    require(entry["name"] == expected_name, "fixture file entries are not canonically ordered")
    require(entry["mode"] == "0600", f"fixture manifest mode is invalid for {expected_name}")
    require_lower_hex(entry["sha256"], f"fixture SHA-256 for {expected_name}")
    require_unsigned(entry["size"], f"fixture size for {expected_name}", maximum=FILE_LIMITS[expected_name])
    require(entry["size"] > 0, f"fixture size is zero for {expected_name}")
    return entry


def validate_summary(value: dict[str, object]) -> tuple[str, dict[str, dict[str, object]]]:
    summary = require_exact_keys(
        value,
        {"files", "nonce_hex", "schema", "schema_version", "semantics", "synthetic_only"},
        "fixture summary",
    )
    require(summary["schema"] == FIXTURE_SCHEMA, "unexpected fixture schema")
    require(
        require_unsigned(summary["schema_version"], "fixture schema version", maximum=SCHEMA_VERSION)
        == SCHEMA_VERSION,
        "unsupported fixture schema version",
    )
    require(summary["synthetic_only"] is True, "fixture is not explicitly synthetic-only")
    nonce_hex = require_lower_hex(summary["nonce_hex"], "fixture nonce")
    semantics = require_exact_keys(
        summary["semantics"],
        {"active_mutated", "backup"},
        "fixture semantics",
    )
    for name, expected in EXPECTED_SEMANTICS.items():
        state = require_exact_keys(
            semantics[name],
            {"generation", "record_count"},
            f"fixture semantics for {name}",
        )
        generation = require_unsigned(state["generation"], f"fixture generation for {name}")
        record_count = require_unsigned(state["record_count"], f"fixture record count for {name}")
        require(
            generation == expected["generation"] and record_count == expected["record_count"],
            f"fixture semantics are invalid for {name}",
        )
    entries = summary["files"]
    require(type(entries) is list, "fixture files must be an array")
    require(len(entries) == len(PAYLOAD_NAMES), "fixture file manifest has the wrong length")
    manifests: dict[str, dict[str, object]] = {}
    for item, name in zip(entries, sorted(PAYLOAD_NAMES), strict=True):
        manifests[name] = validate_manifest_entry(item, name)
    return nonce_hex, manifests


def validate_fixture(root: Path) -> ValidatedFixture:
    require_private_directory(root, "fixture directory")
    try:
        names = {entry.name for entry in root.iterdir()}
    except OSError as error:
        raise FixtureError("cannot enumerate fixture directory") from error
    require(names == FIXTURE_NAMES, "fixture directory contains missing or unexpected entries")

    summary_bytes = read_private_file(
        root / SUMMARY_NAME,
        maximum=MAX_SUMMARY_BYTES,
        label="fixture summary",
    )
    summary = parse_canonical_json(summary_bytes)
    nonce_hex, manifests = validate_summary(summary)
    material = synthetic_material(nonce_hex)
    files: dict[str, bytes] = {}
    for name in PAYLOAD_NAMES:
        contents = read_private_file(
            root / name,
            maximum=FILE_LIMITS[name],
            label=f"fixture file {name}",
        )
        entry = manifests[name]
        require(len(contents) == entry["size"], f"fixture size mismatch for {name}")
        require(sha256_hex(contents) == entry["sha256"], f"fixture hash mismatch for {name}")
        files[name] = contents

    require(
        files[MASTER_PASSWORD_NAME] == material.master_password,
        "fixture master password is not the nonce-derived synthetic value",
    )
    encoded_recovery = recovery_value(files[RECOVERY_NAME])
    assert_no_plaintext(
        (files[ACTIVE_NAME], files[BACKUP_NAME]),
        (*material.plaintext_canaries, encoded_recovery),
    )
    return ValidatedFixture(
        root=root,
        nonce_hex=nonce_hex,
        summary_bytes=summary_bytes,
        summary=summary,
        files=files,
        material=material,
        recovery_value=encoded_recovery,
    )


def copy_fixture_inputs(fixture: ValidatedFixture, destination: Path) -> dict[str, Path]:
    copied: dict[str, Path] = {}
    for name in PAYLOAD_NAMES:
        path = destination / name
        write_exclusive(path, fixture.files[name])
        copied[name] = path
    fsync_directory(destination)
    return copied


def assert_fixture_unchanged(fixture: ValidatedFixture) -> None:
    require_private_directory(fixture.root, "fixture directory after exercise")
    try:
        names = {entry.name for entry in fixture.root.iterdir()}
    except OSError as error:
        raise FixtureError("cannot re-enumerate fixture directory") from error
    require(names == FIXTURE_NAMES, "fixture entries changed during exercise")
    current_summary = read_private_file(
        fixture.root / SUMMARY_NAME,
        maximum=MAX_SUMMARY_BYTES,
        label="fixture summary after exercise",
    )
    require(current_summary == fixture.summary_bytes, "fixture summary changed during exercise")
    for name in PAYLOAD_NAMES:
        current = read_private_file(
            fixture.root / name,
            maximum=FILE_LIMITS[name],
            label=f"fixture file {name} after exercise",
        )
        require(current == fixture.files[name], f"fixture input changed during exercise: {name}")


def result_document(
    fixture: ValidatedFixture,
    *,
    pre_restore: bytes,
    restored: bytes,
) -> dict[str, object]:
    checks = {name: True for name in sorted(EXPECTED_CHECK_NAMES)}
    return {
        "checks": checks,
        "fixture_summary_sha256": sha256_hex(fixture.summary_bytes),
        "hashes": {
            "active_mutated_input_sha256": sha256_hex(fixture.files[ACTIVE_NAME]),
            "backup_input_sha256": sha256_hex(fixture.files[BACKUP_NAME]),
            "final_restored_sha256": sha256_hex(restored),
            "pre_restore_sha256": sha256_hex(pre_restore),
        },
        "nonce_hex": fixture.nonce_hex,
        "outcome": "pass",
        "schema": RESULT_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "semantics": {
            "active_mutated": {"generation": 3, "record_count": 2},
            "backup": {"generation": 2, "record_count": 1},
            "final_restored": {"generation": 2, "record_count": 1},
            "pre_restore": {"generation": 3, "record_count": 2},
        },
        "synthetic_only": True,
    }


def exercise_fixture(
    pvault: Path,
    fixture_root: Path,
    output_result: Path,
    evidence_directory: Path,
) -> None:
    fixture = validate_fixture(fixture_root)
    require(output_result.parent.is_dir(), "result output parent does not exist")
    require(evidence_directory.parent.is_dir(), "evidence directory parent does not exist")
    require(not os.path.lexists(output_result), "result output already exists")
    require(not os.path.lexists(evidence_directory), "evidence directory already exists")
    try:
        resolved_parent = output_result.parent.resolve(strict=True)
        resolved_evidence_parent = evidence_directory.parent.resolve(strict=True)
        resolved_fixture = fixture_root.resolve(strict=True)
    except OSError as error:
        raise FixtureError("cannot resolve fixture, result parent, or evidence parent") from error
    require(
        resolved_parent != resolved_fixture and resolved_fixture not in resolved_parent.parents,
        "result output must not be placed inside the immutable fixture",
    )
    require(
        resolved_evidence_parent != resolved_fixture
        and resolved_fixture not in resolved_evidence_parent.parents,
        "evidence directory must not be placed inside the immutable fixture",
    )
    require(output_result != evidence_directory, "result and evidence paths must be distinct")

    with tempfile.TemporaryDirectory(prefix="pvault-external-fixture-exercise-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        inputs = copy_fixture_inputs(fixture, root)
        environment = isolated_environment(root / "runtime")
        material = fixture.material
        recovery = fixture.recovery_value
        recovery_path = inputs[RECOVERY_NAME]
        backup = inputs[BACKUP_NAME]
        active_mutated = inputs[ACTIVE_NAME]
        restored = root / "restored.pvlt"
        write_exclusive(restored, fixture.files[ACTIVE_NAME])

        verify_snapshot_password(
            pvault,
            backup,
            material,
            recovery,
            cwd=root,
            environment=environment,
            generation=2,
            record_count=1,
            label="external backup password verification",
        )
        verify_snapshot_recovery(
            pvault,
            backup,
            recovery_path,
            material,
            recovery,
            cwd=root,
            environment=environment,
            generation=2,
            record_count=1,
            label="external backup recovery verification",
        )
        verify_snapshot_password(
            pvault,
            active_mutated,
            material,
            recovery,
            cwd=root,
            environment=environment,
            generation=3,
            record_count=2,
            label="external mutated password verification",
        )
        verify_snapshot_recovery(
            pvault,
            active_mutated,
            recovery_path,
            material,
            recovery,
            cwd=root,
            environment=environment,
            generation=3,
            record_count=2,
            label="external mutated recovery verification",
        )
        active_list = list_vault(
            pvault,
            active_mutated,
            material,
            recovery,
            cwd=root,
            environment=environment,
        )
        assert_list_semantics(active_list, material, mutated=True)

        backup_directory = root / "backups"
        pre_restore_before = set(backup_directory.glob("pre-restore-*.pvlt"))
        run_restore(
            pvault,
            restored,
            backup,
            material.master_password,
            cwd=root,
            environment=environment,
            secrets=(*material.secret_canaries, recovery),
        )
        pre_restore_after = set(backup_directory.glob("pre-restore-*.pvlt"))
        created = pre_restore_after - pre_restore_before
        require(len(created) == 1, "restore did not create exactly one pre-restore snapshot")
        pre_restore_path = created.pop()
        require(file_mode(pre_restore_path) == 0o600, "pre-restore snapshot is not mode 0600")
        pre_restore_bytes = pre_restore_path.read_bytes()
        restored_bytes = restored.read_bytes()
        require(
            pre_restore_bytes == fixture.files[ACTIVE_NAME],
            "pre-restore snapshot is not byte-exact to the mutated active input",
        )
        require(
            restored_bytes == fixture.files[BACKUP_NAME],
            "restored vault is not byte-exact to the backup input",
        )
        require(file_mode(restored) == 0o600, "restored vault is not mode 0600")

        verify_snapshot_password(
            pvault,
            pre_restore_path,
            material,
            recovery,
            cwd=root,
            environment=environment,
            generation=3,
            record_count=2,
            label="external pre-restore password verification",
        )
        verify_snapshot_recovery(
            pvault,
            pre_restore_path,
            recovery_path,
            material,
            recovery,
            cwd=root,
            environment=environment,
            generation=3,
            record_count=2,
            label="external pre-restore recovery verification",
        )
        verify_snapshot_password(
            pvault,
            restored,
            material,
            recovery,
            cwd=root,
            environment=environment,
            generation=2,
            record_count=1,
            label="external restored password verification",
        )
        verify_snapshot_recovery(
            pvault,
            restored,
            recovery_path,
            material,
            recovery,
            cwd=root,
            environment=environment,
            generation=2,
            record_count=1,
            label="external restored recovery verification",
        )
        restored_list = list_vault(
            pvault,
            restored,
            material,
            recovery,
            cwd=root,
            environment=environment,
        )
        assert_list_semantics(restored_list, material, mutated=False)

        assert_no_plaintext(
            (pre_restore_bytes, restored_bytes),
            (*material.plaintext_canaries, recovery),
        )
        assert_fixture_unchanged(fixture)
        result_bytes = canonical_json_bytes(
            result_document(
                fixture,
                pre_restore=pre_restore_bytes,
                restored=restored_bytes,
            )
        )
        for secret in (*material.secret_canaries, recovery):
            require(secret not in result_bytes, "synthetic secret appeared in result document")
        publish_evidence(
            evidence_directory,
            pre_restore=pre_restore_bytes,
            final_restored=restored_bytes,
        )
        try:
            write_exclusive(output_result, result_bytes)
            fsync_directory(output_result.parent)
        except BaseException:
            remove_published_evidence(evidence_directory)
            raise

    print(f"external restore fixture exercise: PASS ({output_result}; synthetic data only)")


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or exercise a nonce-bound synthetic PVault restore fixture."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    export_parser = subparsers.add_parser("export", help="create a synthetic fixture")
    export_parser.add_argument("--pvault", required=True, help="PVault executable")
    export_parser.add_argument("--output", required=True, help="new fixture directory")
    export_parser.add_argument("--nonce", required=True, help="256-bit hexadecimal challenge nonce")

    exercise_parser = subparsers.add_parser("exercise", help="exercise a transferred fixture")
    exercise_parser.add_argument("--pvault", required=True, help="PVault executable")
    exercise_parser.add_argument("--fixture", required=True, help="private fixture directory")
    exercise_parser.add_argument("--output-result", required=True, help="new canonical result JSON")
    exercise_parser.add_argument(
        "--evidence-dir",
        required=True,
        help="new private directory for byte-exact restore evidence",
    )
    return parser


def main() -> int:
    os.umask(0o077)
    arguments = argument_parser().parse_args()
    try:
        pvault = validate_pvault(arguments.pvault)
        if arguments.command == "export":
            export_fixture(
                pvault,
                absolute_unresolved(arguments.output),
                normalize_nonce(arguments.nonce),
            )
        elif arguments.command == "exercise":
            exercise_fixture(
                pvault,
                absolute_unresolved(arguments.fixture),
                absolute_unresolved(arguments.output_result),
                absolute_unresolved(arguments.evidence_dir),
            )
        else:  # pragma: no cover - argparse enforces the command set
            fail("unsupported command")
    except (FixtureError, AssertionError, OSError, TimeoutError) as error:
        print(f"external restore fixture: FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
