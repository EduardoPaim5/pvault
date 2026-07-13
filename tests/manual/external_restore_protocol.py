#!/usr/bin/env python3
"""Signed, human-operated attestation for a synthetic cross-machine restore.

The protocol deliberately separates three roles:

* ``prepare`` creates bytes on the source machine and signs a request;
* ``run`` verifies and restores those exact bytes on an independently checked
  out source tree, then signs a closed result with a different key; and
* ``check`` validates the result on the source machine and countersigns a
  receipt.

This is an operational attestation, not cryptographic proof that two physical
computers were used.  The signed claim is intentionally named
``operator-declared-separate-machine``.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import datetime as dt
import errno
import hashlib
import json
import os
import pty
import re
import secrets
import selectors
import select
import signal
import stat
import subprocess
import sys
import tarfile
import termios
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import IO, Iterable, Mapping, NoReturn, Sequence


REPOSITORY = Path(__file__).resolve().parents[2]
CHECK_PUBLICATION = REPOSITORY / "scripts" / "check-publication.sh"

SCHEMA_VERSION = 1
REQUEST_SCHEMA = "pvault.external-restore.request"
RESULT_SCHEMA = "pvault.external-restore.result"
RECEIPT_SCHEMA = "pvault.external-restore.receipt"
CLASSIFICATION = "operator-declared-separate-machine"
LIMITATION = "operator declaration; no physical-separation proof or same-UID hostile-source isolation"

REQUEST_NAMESPACE = "pvault-external-restore-request-v1"
RESULT_NAMESPACE = "pvault-external-restore-result-v1"
RECEIPT_NAMESPACE = "pvault-external-restore-receipt-v1"

REQUEST_JSON = "request.json"
REQUEST_SIGNATURE = "request.json.sig"
RESULT_JSON = "result.json"
RESULT_SIGNATURE = "result.json.sig"
RECEIPT_JSON = "receipt.json"
RECEIPT_SIGNATURE = "receipt.json.sig"
PAYLOAD_DIRECTORY = "payload"

ACTIVE_NAME = "active-mutated.pvlt"
BACKUP_NAME = "backup.pvlt"
MASTER_PASSWORD_NAME = "master-password.bin"
RECOVERY_NAME = "recovery.pvault-recovery"
FIXTURE_SUMMARY_NAME = "fixture-summary.json"
SOURCE_ARCHIVE_NAME = "source.tar"
FIXTURE_NAMES = (
    ACTIVE_NAME,
    BACKUP_NAME,
    FIXTURE_SUMMARY_NAME,
    MASTER_PASSWORD_NAME,
    RECOVERY_NAME,
)
PAYLOAD_NAMES = tuple(sorted((*FIXTURE_NAMES, SOURCE_ARCHIVE_NAME)))
EVIDENCE_NAMES = ("final-restored.pvlt", "pre-restore.pvlt")

MAX_JSON_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 32 * 1024
MAX_PUBLIC_KEY_BYTES = 16 * 1024
MAX_SOURCE_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_VAULT_BYTES = 128 * 1024 * 1024
MAX_RECOVERY_BYTES = 64 * 1024
MAX_MASTER_PASSWORD_BYTES = 256
MAX_ARCHIVE_MEMBERS = 8192
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
MAX_EXTRACTED_BYTES = 64 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
MAX_EXPIRY_HOURS = 168
DEFAULT_EXPIRY_HOURS = 72
CLOCK_SKEW = dt.timedelta(minutes=5)

FILE_LIMITS = {
    ACTIVE_NAME: MAX_VAULT_BYTES,
    BACKUP_NAME: MAX_VAULT_BYTES,
    FIXTURE_SUMMARY_NAME: MAX_JSON_BYTES,
    MASTER_PASSWORD_NAME: MAX_MASTER_PASSWORD_BYTES,
    RECOVERY_NAME: MAX_RECOVERY_BYTES,
    SOURCE_ARCHIVE_NAME: MAX_SOURCE_ARCHIVE_BYTES,
}

LOWER_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
GIT_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
UTC_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

REQUEST_KEYS = frozenset(
    {
        "attestor_key_fingerprint",
        "classification",
        "expires_at",
        "fixture_summary_sha256",
        "git_commit",
        "git_tree",
        "issued_at",
        "nonce_hex",
        "payload",
        "requester_key_fingerprint",
        "schema",
        "schema_version",
        "source_archive_sha256",
        "source_machine_commitment",
        "synthetic_only",
    }
)
RESULT_CHECKS = frozenset(
    {
        "build",
        "evidence_recomputed",
        "final_exact",
        "final_semantics",
        "inputs_unchanged",
        "local_restore_drill",
        "mutated_before_restore",
        "encrypted_artifacts_contain_no_known_plaintext",
        "known_secret_canaries_absent_from_result_json",
        "password_authentication",
        "pre_restore_exact",
        "recovery_authentication",
        "restore",
        "source_archive_matches_local_clean_checkout",
        "no_test_workspace_path_references_before_signing_agent",
    }
)
RESULT_KEYS = frozenset(
    {
        "attested_at",
        "attestor_key_fingerprint",
        "attestor_machine_commitment",
        "checks",
        "classification",
        "declaration",
        "fixture_result_sha256",
        "git_commit",
        "git_tree",
        "hashes",
        "limitation",
        "nonce_hex",
        "request_sha256",
        "requester_key_fingerprint",
        "schema",
        "schema_version",
        "source_machine_commitment",
        "synthetic_only",
    }
)
DECLARATION_KEYS = frozenset(
    {
        "attestor_key_exclusive_to_second_machine",
        "machine_separation_is_operator_attested_only",
        "not_a_container_or_vm_on_the_source_host",
        "tested_source_is_trusted_not_hostile",
        "separate_machine_and_storage",
    }
)
RESULT_HASH_KEYS = frozenset(
    {
        "active_mutated_input_sha256",
        "backup_input_sha256",
        "final_restored_sha256",
        "fixture_summary_sha256",
        "pre_restore_sha256",
        "source_archive_sha256",
    }
)
RECEIPT_KEYS = frozenset(
    {
        "accepted_at",
        "attestor_key_fingerprint",
        "attestor_machine_commitment",
        "classification",
        "decision",
        "limitation",
        "nonce_hex",
        "request_sha256",
        "request_signature_sha256",
        "requester_key_fingerprint",
        "result_sha256",
        "result_signature_sha256",
        "schema",
        "schema_version",
        "source_machine_commitment",
        "synthetic_only",
    }
)

CI_VARIABLES = (
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "BUILDKITE",
    "CIRCLECI",
    "JENKINS_URL",
    "TF_BUILD",
    "TEAMCITY_VERSION",
    "CODEBUILD_BUILD_ID",
    "DRONE",
)


class ProtocolError(RuntimeError):
    """A fail-closed protocol error suitable for a concise terminal message."""


def fail(message: str) -> NoReturn:
    raise ProtocolError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def format_timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(value: object, label: str) -> dt.datetime:
    require(type(value) is str and UTC_TIMESTAMP.fullmatch(value) is not None, f"{label} is invalid")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise ProtocolError(f"{label} is invalid") from error


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_json_number(value: str) -> NoReturn:
    fail(f"forbidden JSON numeric value: {value}")


def validate_json_value(value: object, *, depth: int = 0) -> None:
    require(depth <= 16, "JSON nesting is too deep")
    if type(value) is dict:
        mapping = value
        require(len(mapping) <= 256, "JSON object contains too many fields")
        for key, item in mapping.items():
            require(type(key) is str, "JSON object key is not a string")
            try:
                key.encode("ascii", "strict")
            except UnicodeEncodeError as error:
                raise ProtocolError("JSON object key is not ASCII") from error
            validate_json_value(item, depth=depth + 1)
        return
    if type(value) is list:
        items = value
        require(len(items) <= 8192, "JSON array contains too many items")
        for item in items:
            validate_json_value(item, depth=depth + 1)
        return
    if type(value) is str:
        try:
            value.encode("ascii", "strict")
        except UnicodeEncodeError as error:
            raise ProtocolError("JSON string is not ASCII") from error
        require(len(value) <= MAX_JSON_BYTES, "JSON string is too large")
        return
    if type(value) is bool:
        return
    if type(value) is int:
        require(0 <= value <= (1 << 53) - 1, "JSON integer is outside the supported range")
        return
    fail("JSON contains null, a float, or an unsupported value")


def canonical_json_bytes(value: object) -> bytes:
    validate_json_value(value)
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise ProtocolError("cannot serialize canonical JSON") from error
    data = (rendered + "\n").encode("ascii")
    require(len(data) <= MAX_JSON_BYTES, "canonical JSON exceeds 64 KiB")
    return data


def parse_canonical_json(data: bytes, label: str) -> dict[str, object]:
    require(0 < len(data) <= MAX_JSON_BYTES, f"{label} has an invalid size")
    try:
        text = data.decode("ascii", "strict")
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_float=reject_json_number,
            parse_constant=reject_json_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ProtocolError(f"{label} is not valid canonical JSON") from error
    require(type(value) is dict, f"{label} root must be an object")
    validate_json_value(value)
    require(canonical_json_bytes(value) == data, f"{label} is not byte-canonical JSON")
    return value


def exact_object(value: object, keys: Iterable[str], label: str) -> dict[str, object]:
    require(type(value) is dict, f"{label} must be an object")
    mapping = value
    require(set(mapping) == set(keys), f"{label} contains missing or unknown fields")
    return mapping


def lower_hex(value: object, label: str) -> str:
    require(type(value) is str and LOWER_HEX_64.fullmatch(value) is not None, f"{label} must be 64 lowercase hex characters")
    return value


def git_object_id(value: object, label: str) -> str:
    require(type(value) is str and GIT_OBJECT_ID.fullmatch(value) is not None, f"{label} is not a supported Git object ID")
    return value


def fingerprint_value(value: object, label: str) -> str:
    require(type(value) is str and FINGERPRINT.fullmatch(value) is not None, f"{label} is not an OpenSSH SHA-256 fingerprint")
    return value


def unsigned_integer(value: object, label: str, maximum: int) -> int:
    require(type(value) is int and 0 <= value <= maximum, f"{label} is not a supported unsigned integer")
    return value


def absolute_path(value: str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(value)))


def lstat_path(path: Path, label: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise ProtocolError(f"cannot inspect {label}: {path}") from error


def require_private_directory(path: Path, label: str) -> None:
    metadata = lstat_path(path, label)
    require(stat.S_ISDIR(metadata.st_mode), f"{label} is not a directory")
    require(metadata.st_uid == os.geteuid(), f"{label} is not owned by the current user")
    require(stat.S_IMODE(metadata.st_mode) == 0o700, f"{label} must have mode 0700")


def require_safe_public_file(path: Path, label: str) -> bytes:
    before = lstat_path(path, label)
    require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
    require(before.st_uid in (0, os.geteuid()), f"{label} has an untrusted owner")
    require(before.st_nlink == 1, f"{label} must have exactly one hard link")
    require(stat.S_IMODE(before.st_mode) & 0o022 == 0, f"{label} is group/world writable")
    require(0 < before.st_size <= MAX_PUBLIC_KEY_BYTES, f"{label} has an invalid size")
    return read_file_descriptor_checked(
        path,
        label=label,
        maximum=MAX_PUBLIC_KEY_BYTES,
        expected_modes={stat.S_IMODE(before.st_mode)},
        allowed_owners=(0, os.geteuid()),
    )


def read_file_descriptor_checked(
    path: Path,
    *,
    label: str,
    maximum: int,
    expected_modes: set[int] | None = {0o600},
    allowed_owners: tuple[int, ...] | None = None,
) -> bytes:
    before = lstat_path(path, label)
    owners = allowed_owners if allowed_owners is not None else (os.geteuid(),)
    require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
    require(before.st_uid in owners, f"{label} has an untrusted owner")
    require(before.st_nlink == 1, f"{label} must have exactly one hard link")
    if expected_modes is not None:
        require(stat.S_IMODE(before.st_mode) in expected_modes, f"{label} has an unsafe mode")
    require(0 < before.st_size <= maximum, f"{label} has an invalid size")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProtocolError(f"cannot open {label}") from error
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), f"{label} changed while being opened")
        require(stat.S_ISREG(opened.st_mode), f"opened {label} is not regular")
        require(opened.st_uid in owners and opened.st_nlink == 1, f"opened {label} metadata changed")
        if expected_modes is not None:
            require(stat.S_IMODE(opened.st_mode) in expected_modes, f"opened {label} mode changed")
        require(0 < opened.st_size <= maximum, f"opened {label} size changed")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        require(len(data) == opened.st_size and len(data) <= maximum, f"{label} changed while being read")
        return data
    finally:
        os.close(descriptor)


def write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        require(written > 0, "short write while publishing protocol data")
        view = view[written:]


def write_exclusive(path: Path, data: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        raise ProtocolError(f"cannot create output without replacement: {path}") from error
    try:
        os.fchmod(descriptor, mode)
        write_all(descriptor, data)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        with contextlib.suppress(OSError):
            path.unlink()
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


def create_private_directory(path: Path, label: str) -> None:
    require(not os.path.lexists(path), f"{label} already exists")
    require(path.parent.is_dir(), f"parent of {label} does not exist")
    try:
        path.mkdir(mode=0o700, parents=False, exist_ok=False)
        os.chmod(path, 0o700)
    except OSError as error:
        raise ProtocolError(f"cannot create {label} without replacement: {path}") from error
    require_private_directory(path, label)
    fsync_directory(path.parent)


def exact_directory_entries(path: Path, names: Iterable[str], label: str) -> None:
    require_private_directory(path, label)
    try:
        actual = {entry.name for entry in os.scandir(path)}
    except OSError as error:
        raise ProtocolError(f"cannot enumerate {label}") from error
    require(actual == set(names), f"{label} contains missing or unexpected entries")


def copy_exclusive(source: Path, destination: Path, *, maximum: int, label: str) -> bytes:
    data = read_file_descriptor_checked(source, label=label, maximum=maximum)
    write_exclusive(destination, data)
    return data


def remove_private_tree(path: Path) -> None:
    """Remove only a private tree created inside this protocol invocation."""

    if not os.path.lexists(path):
        return
    require_private_directory(path, "temporary protocol directory")
    for root, directories, files in os.walk(path, topdown=False, followlinks=False):
        root_path = Path(root)
        for name in files:
            child = root_path / name
            metadata = child.lstat()
            require(stat.S_ISREG(metadata.st_mode), "refusing to remove a non-regular temporary artifact")
            child.unlink()
        for name in directories:
            child = root_path / name
            metadata = child.lstat()
            require(stat.S_ISDIR(metadata.st_mode), "refusing to remove a non-directory temporary artifact")
            child.rmdir()
    path.rmdir()


def parse_ed25519_public_key(path: Path, label: str) -> tuple[str, str]:
    data = require_safe_public_file(path, label)
    try:
        text = data.decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise ProtocolError(f"{label} is not ASCII") from error
    lines = [line for line in text.splitlines() if line]
    require(len(lines) == 1, f"{label} must contain exactly one public key")
    require(text in (lines[0], lines[0] + "\n"), f"{label} contains blank or non-canonical lines")
    fields = lines[0].split()
    require(len(fields) >= 2 and fields[0] == "ssh-ed25519", f"{label} must be an ssh-ed25519 public key")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (binascii.Error, ValueError) as error:
        raise ProtocolError(f"{label} has invalid base64") from error
    require(fields[1] == base64.b64encode(blob).decode("ascii"), f"{label} has non-canonical base64")

    def read_string(offset: int) -> tuple[bytes, int]:
        require(offset + 4 <= len(blob), f"{label} has a truncated SSH key blob")
        length = int.from_bytes(blob[offset : offset + 4], "big")
        offset += 4
        require(offset + length <= len(blob), f"{label} has a truncated SSH key field")
        return blob[offset : offset + length], offset + length

    algorithm, position = read_string(0)
    key_bytes, position = read_string(position)
    require(algorithm == b"ssh-ed25519" and len(key_bytes) == 32 and position == len(blob), f"{label} is not a canonical Ed25519 public key")
    normalized = f"ssh-ed25519 {base64.b64encode(blob).decode('ascii')}"
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    require(FINGERPRINT.fullmatch(fingerprint) is not None, f"{label} fingerprint is invalid")
    return normalized, fingerprint


def validate_agent_socket(path: Path, label: str) -> None:
    metadata = lstat_path(path, label)
    require(stat.S_ISSOCK(metadata.st_mode), f"{label} is not a Unix socket")
    require(metadata.st_uid == os.geteuid(), f"{label} is not owned by the current user")


def minimal_environment(*, home: Path | None = None) -> dict[str, str]:
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }
    if home is not None:
        environment["HOME"] = str(home)
    return environment


def command_output(
    arguments: Sequence[str | os.PathLike[str]],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    label: str,
    timeout: float = 180.0,
    stdout_file: IO[bytes] | None = None,
) -> bytes:
    argv = [os.fspath(argument) for argument in arguments]
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=stdout_file if stdout_file is not None else subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise ProtocolError(f"{label} could not be completed") from error

    captured: dict[str, bytearray] = {"stderr": bytearray()}
    streams: dict[int, str] = {}
    selector = selectors.DefaultSelector()
    if process.stderr is not None:
        streams[process.stderr.fileno()] = "stderr"
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(process.stderr, selectors.EVENT_READ)
    if stdout_file is None and process.stdout is not None:
        captured["stdout"] = bytearray()
        streams[process.stdout.fileno()] = "stdout"
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    failure: str | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = f"{label} timed out"
                break
            events = selector.select(min(0.25, remaining))
            for key, _ in events:
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                destination = captured[streams[key.fd]]
                destination.extend(chunk)
                if len(destination) > MAX_COMMAND_OUTPUT_BYTES:
                    failure = f"{label} produced excessive output"
                    break
            if failure is not None:
                break
        if failure is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        try:
            returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            failure = failure or f"{label} timed out"
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    if failure is not None:
        fail(failure)
    stderr = bytes(captured["stderr"])
    stdout = bytes(captured.get("stdout", b""))
    if returncode != 0:
        diagnostic = (stderr or stdout)[-4096:].decode("utf-8", "replace")
        raise ProtocolError(f"{label} failed with exit {returncode}: {diagnostic}")
    return stdout


def ssh_allowed_signers(public_key: str, identity: str, namespace: str) -> bytes:
    require(re.fullmatch(r"[a-z0-9-]+", identity) is not None, "invalid allowed-signers identity")
    require(re.fullmatch(r"[a-z0-9-]+", namespace) is not None, "invalid SSH signature namespace")
    return f'{identity} namespaces="{namespace}" {public_key}\n'.encode("ascii")


def validate_ssh_signature_envelope(signature_bytes: bytes) -> None:
    require(0 < len(signature_bytes) <= MAX_SIGNATURE_BYTES, "SSH signature has an invalid size")
    try:
        text = signature_bytes.decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise ProtocolError("SSH signature envelope is not ASCII") from error
    require("\r" not in text and text.endswith("\n"), "SSH signature envelope has invalid line endings")
    lines = text.splitlines()
    require(
        len(lines) >= 3
        and lines[0] == "-----BEGIN SSH SIGNATURE-----"
        and lines[-1] == "-----END SSH SIGNATURE-----",
        "SSH signature envelope markers are invalid",
    )
    body_lines = lines[1:-1]
    require(all(len(line) == 70 for line in body_lines[:-1]), "SSH signature envelope wrapping is non-canonical")
    require(1 <= len(body_lines[-1]) <= 70, "SSH signature envelope body is empty or oversized")
    encoded = "".join(body_lines)
    require(re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", encoded) is not None, "SSH signature envelope contains invalid base64")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ProtocolError("SSH signature envelope base64 is invalid") from error
    require(decoded.startswith(b"SSHSIG"), "SSH signature envelope lacks the SSHSIG magic")
    canonical_encoded = base64.b64encode(decoded).decode("ascii")
    canonical_lines = [canonical_encoded[index : index + 70] for index in range(0, len(canonical_encoded), 70)]
    canonical = (
        "-----BEGIN SSH SIGNATURE-----\n"
        + "\n".join(canonical_lines)
        + "\n-----END SSH SIGNATURE-----\n"
    ).encode("ascii")
    require(signature_bytes == canonical, "SSH signature envelope is not byte-canonical")


def verify_signature_bytes(
    document_bytes: bytes,
    signature_bytes: bytes,
    *,
    public_key: str,
    identity: str,
    namespace: str,
) -> None:
    require(0 < len(document_bytes) <= MAX_JSON_BYTES, "signed document has an invalid size")
    validate_ssh_signature_envelope(signature_bytes)
    with tempfile.TemporaryDirectory(prefix="pvault-allowed-signers-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        allowed = root / "allowed_signers"
        signature = root / "document.sig"
        write_exclusive(allowed, ssh_allowed_signers(public_key, identity, namespace))
        write_exclusive(signature, signature_bytes)
        environment = minimal_environment(home=root)
        try:
            completed = subprocess.run(
                [
                    "/usr/bin/ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    str(allowed),
                    "-I",
                    identity,
                    "-n",
                    namespace,
                    "-s",
                    str(signature),
                ],
                cwd=root,
                env=environment,
                input=document_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=30,
                start_new_session=True,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ProtocolError("SSH signature verification could not run") from error
        require(completed.returncode == 0, f"invalid SSH signature for namespace {namespace}")


def sign_document(
    document: Path,
    *,
    key_reference: Path,
    public_key: str,
    identity: str,
    namespace: str,
    agent_socket: Path,
) -> Path:
    validate_agent_socket(agent_socket, "SSH signing-agent socket")
    document_before = read_file_descriptor_checked(
        document,
        label="document to sign",
        maximum=MAX_JSON_BYTES,
    )
    signature = Path(str(document) + ".sig")
    require(not os.path.lexists(signature), "signature output already exists")
    environment = minimal_environment(home=document.parent)
    environment["SSH_AUTH_SOCK"] = str(agent_socket)
    command_output(
        [
            "/usr/bin/ssh-keygen",
            "-Y",
            "sign",
            "-f",
            key_reference,
            "-n",
            namespace,
            document,
        ],
        cwd=document.parent,
        environment=environment,
        label=f"SSH signing in namespace {namespace}",
        timeout=30,
    )
    require(os.path.lexists(signature), "ssh-keygen did not produce a signature")
    os.chmod(signature, 0o600)
    fsync_directory(signature.parent)
    document_after = read_file_descriptor_checked(
        document,
        label="document after signing",
        maximum=MAX_JSON_BYTES,
    )
    require(document_after == document_before, "document changed while it was being signed")
    signature_bytes = read_file_descriptor_checked(
        signature,
        label="new SSH signature",
        maximum=MAX_SIGNATURE_BYTES,
    )
    verify_signature_bytes(
        document_before,
        signature_bytes,
        public_key=public_key,
        identity=identity,
        namespace=namespace,
    )
    return signature


def current_agent_socket() -> Path:
    value = os.environ.get("SSH_AUTH_SOCK", "")
    require(value != "", "SSH_AUTH_SOCK is not set; load the signing key in ssh-agent")
    path = absolute_path(value)
    validate_agent_socket(path, "SSH_AUTH_SOCK")
    return path


def reject_automation() -> None:
    require(os.geteuid() != 0, "manual protocol refuses to run as root")
    present = [name for name in CI_VARIABLES if os.environ.get(name)]
    require(not present, f"manual protocol refuses CI/automation environment: {', '.join(present)}")
    require(sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty(), "manual protocol requires terminal stdin/stdout/stderr")
    try:
        descriptor = os.open("/dev/tty", os.O_RDWR | os.O_CLOEXEC)
    except OSError as error:
        raise ProtocolError("manual protocol requires a controlling terminal") from error
    os.close(descriptor)


def prompt_exact(title: str, explanation: Sequence[str], phrase: str) -> None:
    reject_automation()
    with open("/dev/tty", "r+", encoding="utf-8", errors="strict", buffering=1) as terminal:
        terminal.write(f"\nPVault — {title}\n")
        for line in explanation:
            terminal.write(line + "\n")
        terminal.write(f"Para continuar, digite exatamente: {phrase}\n> ")
        terminal.flush()
        response = terminal.readline()
    require(response != "" and response.rstrip("\n") == phrase, "confirmation phrase did not match")


def machine_commitment(nonce_hex: str, machine_id_data: bytes | None = None) -> str:
    lower_hex(nonce_hex, "nonce")
    if machine_id_data is None:
        try:
            machine_id_data = Path("/etc/machine-id").read_bytes()
        except OSError as error:
            raise ProtocolError("cannot read /etc/machine-id for the nonce-salted commitment") from error
    machine_id = machine_id_data.strip()
    require(re.fullmatch(rb"[0-9a-fA-F]{32}", machine_id) is not None, "/etc/machine-id has an unsupported format")
    return sha256_hex(
        b"pvault-external-restore-machine-v1\0"
        + bytes.fromhex(nonce_hex)
        + b"\0"
        + machine_id.lower()
    )


def state_root() -> Path:
    state_value = os.environ.get("XDG_STATE_HOME")
    if state_value:
        base = absolute_path(state_value)
    else:
        home = os.environ.get("HOME")
        require(home is not None and home != "", "HOME is not set")
        base = absolute_path(home) / ".local" / "state"
    try:
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as error:
        raise ProtocolError("cannot create XDG state directory") from error
    base_metadata = lstat_path(base, "XDG state directory")
    require(stat.S_ISDIR(base_metadata.st_mode) and base_metadata.st_uid == os.geteuid(), "XDG state directory is unsafe")
    require(stat.S_IMODE(base_metadata.st_mode) & 0o022 == 0, "XDG state directory is group/world writable")
    current = base
    for component in ("pvault", "external-restore"):
        current = current / component
        if not os.path.lexists(current):
            current.mkdir(mode=0o700)
            os.chmod(current, 0o700)
            fsync_directory(current.parent)
        require_private_directory(current, "protocol state directory")
    return current


def role_ledger(role: str) -> Path:
    require(role in {"pending", "used", "consumed"}, "invalid protocol ledger role")
    path = state_root() / role
    if not os.path.lexists(path):
        path.mkdir(mode=0o700)
        os.chmod(path, 0o700)
        fsync_directory(path.parent)
    require_private_directory(path, f"{role} ledger")
    return path


def write_ledger_entry(role: str, nonce_hex: str, document: Mapping[str, object]) -> Path:
    lower_hex(nonce_hex, "ledger nonce")
    parent = role_ledger(role)
    destination = parent / nonce_hex
    create_private_directory(destination, f"{role} ledger entry")
    try:
        write_exclusive(destination / "ledger.json", canonical_json_bytes(document))
        fsync_directory(destination)
    except BaseException:
        remove_private_tree(destination)
        raise
    return destination


def read_ledger_entry(role: str, nonce_hex: str) -> tuple[Path, dict[str, object]]:
    path = role_ledger(role) / nonce_hex
    exact_directory_entries(path, {"ledger.json"}, f"{role} ledger entry")
    data = read_file_descriptor_checked(path / "ledger.json", label=f"{role} ledger document", maximum=MAX_JSON_BYTES)
    return path, parse_canonical_json(data, f"{role} ledger document")


def git_output(arguments: Sequence[str], label: str) -> bytes:
    return command_output(
        ["/usr/bin/git", "-C", REPOSITORY, *arguments],
        cwd=REPOSITORY,
        environment=minimal_environment(home=absolute_path(os.environ.get("HOME", str(REPOSITORY)))),
        label=label,
        timeout=60,
    )


def validate_repository_clean() -> tuple[str, str]:
    status = git_output(["status", "--porcelain=v1", "--untracked-files=all"], "Git cleanliness check")
    require(status == b"", "repository must be completely clean, including untracked files")
    commit = git_output(["rev-parse", "--verify", "HEAD"], "Git HEAD lookup").decode("ascii").strip()
    tree = git_output(["rev-parse", "--verify", "HEAD^{tree}"], "Git tree lookup").decode("ascii").strip()
    git_object_id(commit, "Git commit")
    git_object_id(tree, "Git tree")
    command_output(
        [CHECK_PUBLICATION],
        cwd=REPOSITORY,
        environment=minimal_environment(home=absolute_path(os.environ.get("HOME", str(REPOSITORY)))),
        label="publication-surface check",
        timeout=60,
    )
    return commit, tree


def create_source_archive(path: Path) -> bytes:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            command_output(
                [
                    "/usr/bin/git",
                    "-C",
                    REPOSITORY,
                    "archive",
                    "--format=tar",
                    "--prefix=pvault-source/",
                    "HEAD",
                ],
                cwd=REPOSITORY,
                environment=minimal_environment(home=absolute_path(os.environ.get("HOME", str(REPOSITORY)))),
                label="Git source archive creation",
                timeout=60,
                stdout_file=output,
            )
            output.flush()
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    data = read_file_descriptor_checked(path, label="source archive", maximum=MAX_SOURCE_ARCHIVE_BYTES)
    return data


def verify_source_archive_against_checkout(
    expected: bytes,
    work: Path,
    regenerated_name: str = "source-regenerated.tar",
) -> None:
    regenerated_path = work / regenerated_name
    regenerated = create_source_archive(regenerated_path)
    require(regenerated == expected, "source.tar is not byte-exact to the independently checked out HEAD")


def safe_extract_source(archive_bytes: bytes, destination: Path) -> Path:
    create_private_directory(destination, "source extraction directory")
    seen: set[str] = set()
    total = 0
    count = 0
    try:
        with tarfile.open(fileobj=__import__("io").BytesIO(archive_bytes), mode="r:") as archive:
            for member in archive:
                count += 1
                require(count <= MAX_ARCHIVE_MEMBERS, "source archive has too many members")
                pure = PurePosixPath(member.name)
                require(not pure.is_absolute(), "source archive contains an absolute path")
                require(pure.parts and pure.parts[0] == "pvault-source", "source archive has an unexpected prefix")
                require(all(part not in ("", ".", "..") for part in pure.parts), "source archive contains an unsafe path")
                normalized = pure.as_posix()
                require(normalized not in seen, "source archive contains a duplicate path")
                seen.add(normalized)
                target = destination.joinpath(*pure.parts)
                require(destination == target or destination in target.parents, "source archive escaped extraction root")
                require(not member.issym() and not member.islnk(), "source archive contains a link")
                require(not member.isdev() and not member.isfifo(), "source archive contains a special file")
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                    os.chmod(target, 0o700)
                    continue
                require(member.isfile(), "source archive contains an unsupported member type")
                require(0 <= member.size <= MAX_ARCHIVE_MEMBER_BYTES, "source archive member exceeds its size limit")
                total += member.size
                require(total <= MAX_EXTRACTED_BYTES, "source archive exceeds the extraction limit")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = archive.extractfile(member)
                require(source is not None, "source archive member could not be read")
                contents = source.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
                require(len(contents) == member.size, "source archive member is truncated or oversized")
                mode = 0o700 if member.mode & 0o111 else 0o600
                write_exclusive(target, contents, mode)
        root = destination / "pvault-source"
        require_private_directory(root, "extracted source root")
        require((root / "CMakeLists.txt").is_file(), "source archive lacks CMakeLists.txt")
        fsync_directory(destination)
        return root
    except BaseException:
        with contextlib.suppress(BaseException):
            remove_private_tree(destination)
        raise


def payload_manifest_entry(name: str, data: bytes) -> dict[str, object]:
    return {"mode": "0600", "name": name, "sha256": sha256_hex(data), "size": len(data)}


def validate_payload_manifest(value: object) -> dict[str, dict[str, object]]:
    require(type(value) is list and len(value) == len(PAYLOAD_NAMES), "request payload manifest has the wrong length")
    result: dict[str, dict[str, object]] = {}
    for item, expected_name in zip(value, PAYLOAD_NAMES, strict=True):
        entry = exact_object(item, {"mode", "name", "sha256", "size"}, "payload manifest entry")
        require(entry["name"] == expected_name, "payload manifest is not in canonical name order")
        require(entry["mode"] == "0600", f"payload mode is invalid for {expected_name}")
        lower_hex(entry["sha256"], f"payload hash for {expected_name}")
        size = unsigned_integer(entry["size"], f"payload size for {expected_name}", FILE_LIMITS[expected_name])
        require(size > 0, f"payload size is zero for {expected_name}")
        result[expected_name] = entry
    return result


def validate_fixture_summary(
    data: bytes,
    *,
    nonce_hex: str,
    payload: Mapping[str, Mapping[str, object]],
) -> None:
    summary = parse_canonical_json(data, "fixture summary")
    summary = exact_object(
        summary,
        {"files", "nonce_hex", "schema", "schema_version", "semantics", "synthetic_only"},
        "fixture summary",
    )
    require(summary["schema"] == "pvault.external-restore.fixture", "unsupported fixture schema")
    require(unsigned_integer(summary["schema_version"], "fixture schema version", SCHEMA_VERSION) == SCHEMA_VERSION, "unsupported fixture schema version")
    require(summary["nonce_hex"] == nonce_hex, "fixture nonce does not match the request")
    require(summary["synthetic_only"] is True, "fixture is not synthetic-only")
    semantics = exact_object(summary["semantics"], {"active_mutated", "backup"}, "fixture semantics")
    expected_semantics = {
        "active_mutated": {"generation": 3, "record_count": 2},
        "backup": {"generation": 2, "record_count": 1},
    }
    for name, expected in expected_semantics.items():
        state = exact_object(semantics[name], {"generation", "record_count"}, f"fixture semantics {name}")
        require(state == expected, f"fixture semantics are invalid for {name}")
    expected_names = tuple(sorted((ACTIVE_NAME, BACKUP_NAME, MASTER_PASSWORD_NAME, RECOVERY_NAME)))
    files = summary["files"]
    require(type(files) is list and len(files) == len(expected_names), "fixture file manifest has the wrong length")
    for item, name in zip(files, expected_names, strict=True):
        entry = exact_object(item, {"mode", "name", "sha256", "size"}, "fixture file entry")
        require(entry["name"] == name and entry["mode"] == "0600", "fixture file manifest order or mode is invalid")
        lower_hex(entry["sha256"], f"fixture hash for {name}")
        unsigned_integer(entry["size"], f"fixture size for {name}", FILE_LIMITS[name])
        require(entry["sha256"] == payload[name]["sha256"] and entry["size"] == payload[name]["size"], f"fixture manifest does not bind payload {name}")


def validate_request_document(value: dict[str, object]) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    request = exact_object(value, REQUEST_KEYS, "request")
    require(request["schema"] == REQUEST_SCHEMA, "unsupported request schema")
    require(unsigned_integer(request["schema_version"], "request schema version", SCHEMA_VERSION) == SCHEMA_VERSION, "unsupported request schema version")
    require(request["classification"] == CLASSIFICATION, "unsupported request classification")
    require(request["synthetic_only"] is True, "request is not synthetic-only")
    lower_hex(request["nonce_hex"], "request nonce")
    git_object_id(request["git_commit"], "request Git commit")
    git_object_id(request["git_tree"], "request Git tree")
    require(len(request["git_commit"]) == len(request["git_tree"]), "request Git object ID lengths differ")
    lower_hex(request["source_machine_commitment"], "source-machine commitment")
    fingerprint_value(request["requester_key_fingerprint"], "requester fingerprint")
    fingerprint_value(request["attestor_key_fingerprint"], "attestor fingerprint")
    require(request["requester_key_fingerprint"] != request["attestor_key_fingerprint"], "requester and attestor keys must differ")
    issued = parse_timestamp(request["issued_at"], "request issue time")
    expires = parse_timestamp(request["expires_at"], "request expiry time")
    require(issued < expires <= issued + dt.timedelta(hours=MAX_EXPIRY_HOURS), "request expiry interval is invalid")
    payload = validate_payload_manifest(request["payload"])
    source_hash = lower_hex(request["source_archive_sha256"], "source archive hash")
    fixture_hash = lower_hex(request["fixture_summary_sha256"], "fixture summary hash")
    require(payload[SOURCE_ARCHIVE_NAME]["sha256"] == source_hash, "source archive hash is inconsistent with payload manifest")
    require(payload[FIXTURE_SUMMARY_NAME]["sha256"] == fixture_hash, "fixture summary hash is inconsistent with payload manifest")
    return request, payload


def read_request_directory(
    request_directory: Path,
    *,
    requester_public_key: str,
) -> tuple[dict[str, object], dict[str, dict[str, object]], dict[str, bytes], bytes, bytes]:
    exact_directory_entries(
        request_directory,
        {REQUEST_JSON, REQUEST_SIGNATURE, PAYLOAD_DIRECTORY},
        "request directory",
    )
    payload_directory = request_directory / PAYLOAD_DIRECTORY
    exact_directory_entries(payload_directory, PAYLOAD_NAMES, "request payload directory")
    request_bytes = read_file_descriptor_checked(
        request_directory / REQUEST_JSON,
        label="request JSON",
        maximum=MAX_JSON_BYTES,
    )
    signature_bytes = read_file_descriptor_checked(
        request_directory / REQUEST_SIGNATURE,
        label="request signature",
        maximum=MAX_SIGNATURE_BYTES,
    )
    request, manifest = validate_request_document(parse_canonical_json(request_bytes, "request JSON"))
    verify_signature_bytes(
        request_bytes,
        signature_bytes,
        public_key=requester_public_key,
        identity="pvault-requester",
        namespace=REQUEST_NAMESPACE,
    )
    payload: dict[str, bytes] = {}
    for name in PAYLOAD_NAMES:
        data = read_file_descriptor_checked(
            payload_directory / name,
            label=f"request payload {name}",
            maximum=FILE_LIMITS[name],
        )
        require(len(data) == manifest[name]["size"], f"payload size mismatch for {name}")
        require(sha256_hex(data) == manifest[name]["sha256"], f"payload hash mismatch for {name}")
        payload[name] = data
    validate_fixture_summary(
        payload[FIXTURE_SUMMARY_NAME],
        nonce_hex=request["nonce_hex"],
        payload=manifest,
    )
    return request, manifest, payload, request_bytes, signature_bytes


def validate_fixture_result(
    value: dict[str, object],
    *,
    request: Mapping[str, object],
    payload: Mapping[str, bytes],
    pre_restore: bytes,
    final_restored: bytes,
) -> dict[str, str]:
    result = exact_object(
        value,
        {
            "checks",
            "fixture_summary_sha256",
            "hashes",
            "nonce_hex",
            "outcome",
            "schema",
            "schema_version",
            "semantics",
            "synthetic_only",
        },
        "fixture result",
    )
    require(result["schema"] == "pvault.external-restore.exercise-result", "unsupported fixture result schema")
    require(unsigned_integer(result["schema_version"], "fixture result schema version", SCHEMA_VERSION) == SCHEMA_VERSION, "unsupported fixture result schema version")
    require(result["nonce_hex"] == request["nonce_hex"], "fixture result nonce mismatch")
    require(result["outcome"] == "pass" and result["synthetic_only"] is True, "fixture exercise did not pass as synthetic-only")
    expected_fixture_checks = {
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
    checks = exact_object(result["checks"], expected_fixture_checks, "fixture checks")
    require(all(value is True for value in checks.values()), "fixture result contains a failed check")
    semantics = exact_object(
        result["semantics"],
        {"active_mutated", "backup", "final_restored", "pre_restore"},
        "fixture result semantics",
    )
    expected_semantics = {
        "active_mutated": {"generation": 3, "record_count": 2},
        "backup": {"generation": 2, "record_count": 1},
        "final_restored": {"generation": 2, "record_count": 1},
        "pre_restore": {"generation": 3, "record_count": 2},
    }
    require(semantics == expected_semantics, "fixture result semantics are invalid")
    hashes_object = exact_object(
        result["hashes"],
        {
            "active_mutated_input_sha256",
            "backup_input_sha256",
            "final_restored_sha256",
            "pre_restore_sha256",
        },
        "fixture result hashes",
    )
    hashes: dict[str, str] = {}
    for name, hash_value in hashes_object.items():
        hashes[name] = lower_hex(hash_value, f"fixture result hash {name}")
    expected = {
        "active_mutated_input_sha256": sha256_hex(payload[ACTIVE_NAME]),
        "backup_input_sha256": sha256_hex(payload[BACKUP_NAME]),
        "final_restored_sha256": sha256_hex(final_restored),
        "pre_restore_sha256": sha256_hex(pre_restore),
    }
    require(hashes == expected, "fixture result hashes were not independently reproduced")
    require(pre_restore == payload[ACTIVE_NAME], "pre-restore evidence is not byte-exact to source mutated bytes")
    require(final_restored == payload[BACKUP_NAME], "final evidence is not byte-exact to source backup bytes")
    fixture_summary_hash = lower_hex(result["fixture_summary_sha256"], "fixture summary hash in result")
    require(fixture_summary_hash == sha256_hex(payload[FIXTURE_SUMMARY_NAME]), "fixture summary hash mismatch in result")
    return hashes


def validate_result_document(value: dict[str, object]) -> dict[str, object]:
    result = exact_object(value, RESULT_KEYS, "external restore result")
    require(result["schema"] == RESULT_SCHEMA, "unsupported result schema")
    require(unsigned_integer(result["schema_version"], "result schema version", SCHEMA_VERSION) == SCHEMA_VERSION, "unsupported result schema version")
    require(result["classification"] == CLASSIFICATION, "unsupported result classification")
    require(result["synthetic_only"] is True, "result is not synthetic-only")
    require(result["limitation"] == LIMITATION, "result limitation is missing or changed")
    lower_hex(result["nonce_hex"], "result nonce")
    lower_hex(result["request_sha256"], "result request hash")
    lower_hex(result["source_machine_commitment"], "result source commitment")
    lower_hex(result["attestor_machine_commitment"], "result attestor commitment")
    require(result["source_machine_commitment"] != result["attestor_machine_commitment"], "source and attestor commitments are equal")
    git_object_id(result["git_commit"], "result Git commit")
    git_object_id(result["git_tree"], "result Git tree")
    require(len(result["git_commit"]) == len(result["git_tree"]), "result Git object ID lengths differ")
    fingerprint_value(result["requester_key_fingerprint"], "result requester fingerprint")
    fingerprint_value(result["attestor_key_fingerprint"], "result attestor fingerprint")
    require(result["requester_key_fingerprint"] != result["attestor_key_fingerprint"], "result uses the same key for both roles")
    parse_timestamp(result["attested_at"], "result attestation time")
    lower_hex(result["fixture_result_sha256"], "fixture result hash")
    declaration = exact_object(result["declaration"], DECLARATION_KEYS, "operator declaration")
    require(all(value is True for value in declaration.values()), "operator declaration is incomplete")
    checks = exact_object(result["checks"], RESULT_CHECKS, "result checks")
    require(all(value is True for value in checks.values()), "external result contains a failed check")
    hashes = exact_object(result["hashes"], RESULT_HASH_KEYS, "result hashes")
    for name, hash_value in hashes.items():
        lower_hex(hash_value, f"result hash {name}")
    return result


def output_path_outside_repository(
    value: str,
    label: str,
    *,
    allow_existing: bool = False,
) -> Path:
    path = absolute_path(value)
    try:
        parent = path.parent.resolve(strict=True)
        repository = REPOSITORY.resolve(strict=True)
    except OSError as error:
        raise ProtocolError(f"cannot resolve parent of {label}") from error
    resolved_candidate = parent / path.name
    require(resolved_candidate != repository and repository not in resolved_candidate.parents, f"{label} must be outside the Git repository")
    if os.path.lexists(resolved_candidate):
        require(allow_existing, f"{label} already exists")
        require_private_directory(resolved_candidate, label)
    parent_metadata = lstat_path(parent, f"parent of {label}")
    require(stat.S_ISDIR(parent_metadata.st_mode), f"parent of {label} is not a directory")
    require(parent_metadata.st_uid == os.geteuid(), f"parent of {label} is not owned by the current user")
    require(stat.S_IMODE(parent_metadata.st_mode) & 0o022 == 0, f"parent of {label} is group/world writable")
    return resolved_candidate


def build_pvault(source: Path, build: Path, work_home: Path) -> Path:
    work_home.mkdir(mode=0o700, exist_ok=False)
    environment = minimal_environment(home=work_home)
    command_output(
        [
            "/usr/bin/cmake",
            "-S",
            source,
            "-B",
            build,
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Debug",
            "-DBUILD_TESTING=OFF",
            "-DPVAULT_ENABLE_HARDENING=ON",
            "-DPVAULT_ENABLE_SANITIZERS=OFF",
            "-DPVAULT_BUILD_FUZZERS=OFF",
            "-DPVAULT_WARNINGS_AS_ERRORS=ON",
        ],
        cwd=source,
        environment=environment,
        label="PVault external-restore configure",
        timeout=120,
    )
    command_output(
        ["/usr/bin/cmake", "--build", build, "--parallel", "--target", "pvault"],
        cwd=source,
        environment=environment,
        label="PVault external-restore build",
        timeout=300,
    )
    executable = build / "pvault"
    metadata = lstat_path(executable, "built PVault executable")
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid(), "built PVault executable is unsafe")
    require(os.access(executable, os.X_OK), "built PVault executable is not executable")
    return executable


def run_fixture_export(
    helper: Path,
    source: Path,
    pvault: Path,
    output: Path,
    nonce_hex: str,
    home: Path,
) -> None:
    environment = minimal_environment(home=home)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    output_bytes = command_output(
        [
            "/usr/bin/python3",
            helper,
            "export",
            "--pvault",
            pvault,
            "--output",
            output,
            "--nonce",
            nonce_hex,
        ],
        cwd=source,
        environment=environment,
        label="synthetic external fixture export",
        timeout=180,
    )
    require(b"external restore fixture export: PASS" in output_bytes, "fixture export did not report PASS")


def run_local_restore_drill(source: Path, pvault: Path, home: Path) -> None:
    environment = minimal_environment(home=home)
    environment["PVAULT_BUILD_DIR"] = str(pvault.parent)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    output = command_output(
        ["/usr/bin/python3", source / "tests" / "integration" / "restore_drill.py"],
        cwd=source,
        environment=environment,
        label="local restore drill on the external machine",
        timeout=180,
    )
    require(b"restore drill: PASS" in output, "local restore drill did not report PASS")


def run_fixture_exercise(
    helper: Path,
    source: Path,
    pvault: Path,
    fixture_directory: Path,
    result_path: Path,
    evidence_directory: Path,
    home: Path,
) -> None:
    environment = minimal_environment(home=home)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    output = command_output(
        [
            "/usr/bin/python3",
            helper,
            "exercise",
            "--pvault",
            pvault,
            "--fixture",
            fixture_directory,
            "--output-result",
            result_path,
            "--evidence-dir",
            evidence_directory,
        ],
        cwd=source,
        environment=environment,
        label="external restore fixture exercise",
        timeout=240,
    )
    require(b"external restore fixture exercise: PASS" in output, "external fixture exercise did not report PASS")


def redact(data: bytes, secrets_to_redact: Sequence[bytes]) -> bytes:
    redacted = data
    for secret in secrets_to_redact:
        if secret:
            redacted = redacted.replace(secret, b"<redacted>")
    return redacted


def pty_command(
    arguments: Sequence[str | os.PathLike[str]],
    *,
    dialogues: Sequence[tuple[bytes, bytes, bool]],
    secrets_to_protect: Sequence[bytes],
    cwd: Path,
    environment: Mapping[str, str],
    label: str,
    timeout: float = 30.0,
) -> bytes:
    argv = [os.fspath(argument) for argument in arguments]
    argv_blob = b"\0".join(os.fsencode(argument) for argument in argv)
    environment_blob = b"\0".join(
        os.fsencode(name) + b"=" + os.fsencode(value)
        for name, value in environment.items()
    )
    for secret in secrets_to_protect:
        require(secret not in argv_blob, f"{label}: secret is present in constructed argv")
        require(secret not in environment_blob, f"{label}: secret is present in constructed environment")

    try:
        pid, master_fd = pty.fork()
    except OSError as error:
        raise ProtocolError(f"{label}: could not create a controlling PTY") from error
    if pid == 0:  # pragma: no cover - child-only path
        try:
            os.chdir(cwd)
            os.execvpe(argv[0], argv, dict(environment))
        except BaseException as error:
            os.write(2, f"PTY exec failed: {error}\n".encode("utf-8", "replace"))
            os._exit(127)

    os.set_blocking(master_fd, False)
    output = bytearray()
    search_position = 0
    dialogue_index = 0
    returncode: int | None = None
    eof = False
    deadline = time.monotonic() + timeout

    def invocation_is_clean() -> None:
        for proc_name in ("cmdline", "environ"):
            try:
                proc_data = Path(f"/proc/{pid}/{proc_name}").read_bytes()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            for secret in secrets_to_protect:
                require(secret not in proc_data, f"{label}: secret appeared in /proc/{proc_name}")

    def terminate() -> None:
        if returncode is not None:
            return
        try:
            process_group = os.getpgid(pid)
            if process_group != os.getpgrp():
                os.killpg(process_group, signal.SIGKILL)
            else:
                os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    try:
        while True:
            while dialogue_index < len(dialogues):
                prompt, response, expected_echo = dialogues[dialogue_index]
                position = output.find(prompt, search_position)
                if position < 0:
                    break
                search_position = position + len(prompt)
                try:
                    echo_enabled = bool(termios.tcgetattr(master_fd)[3] & termios.ECHO)
                except termios.error as error:
                    raise ProtocolError(f"{label}: cannot inspect terminal echo") from error
                require(echo_enabled is expected_echo, f"{label}: terminal echo state is wrong at a prompt")
                invocation_is_clean()
                os.write(master_fd, response + b"\n")
                dialogue_index += 1

            if returncode is not None and eof:
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate()
                fail(f"{label}: timed out; output={redact(bytes(output), secrets_to_protect)[-2048:]!r}")
            readable, _, _ = select.select([master_fd] if not eof else [], [], [], min(0.05, remaining))
            if readable:
                try:
                    chunk = os.read(master_fd, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        eof = True
                        chunk = b""
                    elif error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        chunk = b""
                    else:
                        raise
                if chunk:
                    output.extend(chunk)
                    require(len(output) <= MAX_COMMAND_OUTPUT_BYTES, f"{label}: terminal output exceeded its limit")
                elif not chunk and returncode is not None:
                    eof = True
            if returncode is None:
                waited, status = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    returncode = os.waitstatus_to_exitcode(status)
            if returncode is not None and not readable:
                try:
                    chunk = os.read(master_fd, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        eof = True
                        continue
                    if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        continue
                    raise
                if chunk:
                    output.extend(chunk)
                    require(len(output) <= MAX_COMMAND_OUTPUT_BYTES, f"{label}: terminal output exceeded its limit")
                else:
                    eof = True
        require(dialogue_index == len(dialogues), f"{label}: process exited before all prompts")
        require(returncode == 0, f"{label}: command failed ({returncode}); output={redact(bytes(output), secrets_to_protect)[-2048:]!r}")
        for secret in secrets_to_protect:
            require(secret not in output, f"{label}: secret appeared in terminal output")
        try:
            echo_enabled = bool(termios.tcgetattr(master_fd)[3] & termios.ECHO)
        except termios.error as error:
            raise ProtocolError(f"{label}: cannot inspect final terminal echo state") from error
        require(echo_enabled, f"{label}: terminal echo was not restored")
        return bytes(output)
    except BaseException:
        terminate()
        if returncode is None:
            with contextlib.suppress(ChildProcessError):
                os.waitpid(pid, 0)
        raise
    finally:
        os.close(master_fd)


def assert_snapshot_output(output: bytes, *, generation: int, record_count: int, label: str) -> None:
    require(b"Authenticated snapshot" in output, f"{label}: snapshot did not authenticate")
    require(f"Generation: {generation}".encode("ascii") in output, f"{label}: wrong generation")
    require(f"Record count: {record_count}".encode("ascii") in output, f"{label}: wrong record count")


def independently_verify_snapshot(
    pvault: Path,
    snapshot: Path,
    recovery_path: Path,
    master_password: bytes,
    secrets_to_protect: Sequence[bytes],
    *,
    generation: int,
    record_count: int,
    cwd: Path,
    environment: Mapping[str, str],
    label: str,
) -> None:
    password_output = pty_command(
        [pvault, "rescue", "verify", snapshot],
        dialogues=((b"Master password for snapshot: ", master_password, False),),
        secrets_to_protect=secrets_to_protect,
        cwd=cwd,
        environment=environment,
        label=f"{label} password verification",
    )
    assert_snapshot_output(
        password_output,
        generation=generation,
        record_count=record_count,
        label=f"{label} password verification",
    )
    recovery_output = pty_command(
        [pvault, "rescue", "verify", snapshot, "--recovery", recovery_path],
        dialogues=(),
        secrets_to_protect=secrets_to_protect,
        cwd=cwd,
        environment=environment,
        label=f"{label} recovery verification",
    )
    assert_snapshot_output(
        recovery_output,
        generation=generation,
        record_count=record_count,
        label=f"{label} recovery verification",
    )


def independent_restore_exercise(
    root: Path,
    *,
    pvault: Path,
    payload: Mapping[str, bytes],
    nonce_hex: str,
) -> tuple[bytes, bytes]:
    exercise = root / "independent-restore"
    create_private_directory(exercise, "independent restore workspace")
    active = exercise / ACTIVE_NAME
    backup = exercise / BACKUP_NAME
    recovery_path = exercise / RECOVERY_NAME
    target = exercise / "restored.pvlt"
    write_exclusive(active, payload[ACTIVE_NAME])
    write_exclusive(backup, payload[BACKUP_NAME])
    write_exclusive(recovery_path, payload[RECOVERY_NAME])
    write_exclusive(target, payload[ACTIVE_NAME])
    master_password = payload[MASTER_PASSWORD_NAME]
    protected = (*derived_plaintext_canaries(nonce_hex), recovery_canary(payload[RECOVERY_NAME]))
    environment = minimal_environment(home=exercise / "home")
    Path(environment["HOME"]).mkdir(mode=0o700)
    environment["TERM"] = "xterm"
    environment["XDG_CONFIG_HOME"] = str(exercise / "config")
    environment["XDG_DATA_HOME"] = str(exercise / "data")
    Path(environment["XDG_CONFIG_HOME"]).mkdir(mode=0o700)
    Path(environment["XDG_DATA_HOME"]).mkdir(mode=0o700)

    independently_verify_snapshot(
        pvault,
        active,
        recovery_path,
        master_password,
        protected,
        generation=3,
        record_count=2,
        cwd=exercise,
        environment=environment,
        label="mutated source input",
    )
    independently_verify_snapshot(
        pvault,
        backup,
        recovery_path,
        master_password,
        protected,
        generation=2,
        record_count=1,
        cwd=exercise,
        environment=environment,
        label="backup source input",
    )

    input_hashes = {
        ACTIVE_NAME: sha256_hex(read_file_descriptor_checked(active, label="independent active input", maximum=MAX_VAULT_BYTES)),
        BACKUP_NAME: sha256_hex(read_file_descriptor_checked(backup, label="independent backup input", maximum=MAX_VAULT_BYTES)),
        RECOVERY_NAME: sha256_hex(read_file_descriptor_checked(recovery_path, label="independent recovery input", maximum=MAX_RECOVERY_BYTES)),
    }
    pty_command(
        [pvault, "--vault", target, "restore", backup],
        dialogues=(
            (b"Master password for backup: ", master_password, False),
            (b"Restore this authenticated backup? [y/N]: ", b"y", True),
        ),
        secrets_to_protect=protected,
        cwd=exercise,
        environment=environment,
        label="independent restore",
    )
    backups_directory = exercise / "backups"
    try:
        pre_restore_paths = list(backups_directory.glob("pre-restore-*.pvlt"))
    except OSError as error:
        raise ProtocolError("cannot enumerate independent pre-restore snapshots") from error
    require(len(pre_restore_paths) == 1, "independent restore did not create exactly one pre-restore snapshot")
    pre_restore_path = pre_restore_paths[0]
    pre_restore = read_file_descriptor_checked(
        pre_restore_path,
        label="independent pre-restore snapshot",
        maximum=MAX_VAULT_BYTES,
    )
    final_restored = read_file_descriptor_checked(
        target,
        label="independent final restored vault",
        maximum=MAX_VAULT_BYTES,
    )
    require(pre_restore == payload[ACTIVE_NAME], "independent pre-restore bytes differ from source mutated bytes")
    require(final_restored == payload[BACKUP_NAME], "independent final bytes differ from source backup bytes")
    require(
        input_hashes
        == {
            ACTIVE_NAME: sha256_hex(read_file_descriptor_checked(active, label="active input after independent restore", maximum=MAX_VAULT_BYTES)),
            BACKUP_NAME: sha256_hex(read_file_descriptor_checked(backup, label="backup input after independent restore", maximum=MAX_VAULT_BYTES)),
            RECOVERY_NAME: sha256_hex(read_file_descriptor_checked(recovery_path, label="recovery input after independent restore", maximum=MAX_RECOVERY_BYTES)),
        },
        "independent restore modified an immutable input",
    )
    independently_verify_snapshot(
        pvault,
        pre_restore_path,
        recovery_path,
        master_password,
        protected,
        generation=3,
        record_count=2,
        cwd=exercise,
        environment=environment,
        label="independent pre-restore",
    )
    independently_verify_snapshot(
        pvault,
        target,
        recovery_path,
        master_password,
        protected,
        generation=2,
        record_count=1,
        cwd=exercise,
        environment=environment,
        label="independent final restore",
    )
    for encrypted in (active.read_bytes(), backup.read_bytes(), pre_restore, final_restored):
        for canary in protected:
            require(canary not in encrypted, "known plaintext canary appeared in an encrypted artifact")
    return pre_restore, final_restored


def publish_request_directory(
    destination: Path,
    *,
    payload: Mapping[str, bytes],
    request_bytes: bytes,
    signature_bytes: bytes,
) -> None:
    create_private_directory(destination, "request output directory")
    payload_directory = destination / PAYLOAD_DIRECTORY
    try:
        create_private_directory(payload_directory, "request payload output directory")
        for name in PAYLOAD_NAMES:
            write_exclusive(payload_directory / name, payload[name])
        write_exclusive(destination / REQUEST_JSON, request_bytes)
        write_exclusive(destination / REQUEST_SIGNATURE, signature_bytes)
        fsync_directory(payload_directory)
        fsync_directory(destination)
    except BaseException:
        with contextlib.suppress(BaseException):
            remove_private_tree(destination)
        raise


def publish_signed_pair(
    destination: Path,
    *,
    document_name: str,
    document_bytes: bytes,
    signature_name: str,
    signature_bytes: bytes,
    label: str,
) -> None:
    require(not os.path.lexists(destination), f"{label} already exists")
    staging = destination.parent / f".{destination.name}.{secrets.token_hex(8)}.staging"
    create_private_directory(staging, f"{label} staging directory")
    try:
        write_exclusive(staging / document_name, document_bytes)
        write_exclusive(staging / signature_name, signature_bytes)
        fsync_directory(staging)
        require(not os.path.lexists(destination), f"{label} appeared concurrently")
        os.rename(staging, destination)
        fsync_directory(destination.parent)
    except OSError as error:
        with contextlib.suppress(BaseException):
            remove_private_tree(staging)
        raise ProtocolError(f"could not atomically publish {label}") from error
    except BaseException:
        with contextlib.suppress(BaseException):
            remove_private_tree(staging)
        raise


def publish_or_validate_signed_pair(
    destination: Path,
    *,
    document_name: str,
    document_bytes: bytes,
    signature_name: str,
    signature_bytes: bytes,
    label: str,
) -> None:
    if not os.path.lexists(destination):
        publish_signed_pair(
            destination,
            document_name=document_name,
            document_bytes=document_bytes,
            signature_name=signature_name,
            signature_bytes=signature_bytes,
            label=label,
        )
        return
    exact_directory_entries(destination, {document_name, signature_name}, label)
    existing_document = read_file_descriptor_checked(
        destination / document_name,
        label=f"existing {document_name}",
        maximum=MAX_JSON_BYTES,
    )
    existing_signature = read_file_descriptor_checked(
        destination / signature_name,
        label=f"existing {signature_name}",
        maximum=MAX_SIGNATURE_BYTES,
    )
    require(
        existing_document == document_bytes and existing_signature == signature_bytes,
        f"{label} exists with different bytes",
    )


def fixture_directory_from_payload(root: Path, payload: Mapping[str, bytes]) -> Path:
    fixture = root / "fixture"
    create_private_directory(fixture, "private fixture copy")
    for name in FIXTURE_NAMES:
        write_exclusive(fixture / name, payload[name])
    fsync_directory(fixture)
    return fixture


def secure_file_snapshot(request_directory: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in PAYLOAD_NAMES:
        data = read_file_descriptor_checked(
            request_directory / PAYLOAD_DIRECTORY / name,
            label=f"request payload snapshot {name}",
            maximum=FILE_LIMITS[name],
        )
        result[name] = sha256_hex(data)
    return result


def ensure_workspace_quiescent(work: Path) -> None:
    prefix = str(work.resolve(strict=True))
    own_pid = os.getpid()
    offenders: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == own_pid:
            continue
        pid = int(entry.name)
        try:
            metadata = entry.stat()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if metadata.st_uid != os.geteuid():
            continue
        paths: list[str] = []
        for name in ("cwd", "exe", "root"):
            with contextlib.suppress(OSError):
                paths.append(os.readlink(entry / name))
        try:
            for descriptor in (entry / "fd").iterdir():
                with contextlib.suppress(OSError):
                    paths.append(os.readlink(descriptor))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            pass
        if any(path == prefix or path.startswith(prefix + os.sep) for path in paths):
            offenders.append(pid)
    require(not offenders, f"test workspace is still held by process IDs: {offenders}")


@contextlib.contextmanager
def dedicated_signing_agent(work: Path) -> Iterable[Path]:
    require(not os.environ.get("SSH_AUTH_SOCK") and not os.environ.get("SSH_AGENT_PID"), "external run must start with SSH_AUTH_SOCK and SSH_AGENT_PID unset")
    socket = work / "attestor-agent.sock"
    environment = minimal_environment(home=work)
    try:
        agent = subprocess.Popen(
            ["/usr/bin/ssh-agent", "-D", "-a", str(socket)],
            cwd=work,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as error:
        raise ProtocolError("could not start a dedicated post-test ssh-agent") from error
    try:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and agent.poll() is None and not os.path.exists(socket):
            time.sleep(0.05)
        require(agent.poll() is None and os.path.exists(socket), "dedicated post-test ssh-agent did not start")
        validate_agent_socket(socket, "dedicated post-test ssh-agent socket")
        yield socket
    finally:
        if agent.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(agent.pid, signal.SIGTERM)
            try:
                agent.wait(timeout=5)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(agent.pid, signal.SIGKILL)
                agent.wait(timeout=5)


def prepare_command(arguments: argparse.Namespace) -> None:
    reject_automation()
    requester_key_path = absolute_path(arguments.requester_key)
    attestor_key_path = absolute_path(arguments.attestor_pub)
    requester_public, requester_fingerprint = parse_ed25519_public_key(requester_key_path, "requester public key")
    _, attestor_fingerprint = parse_ed25519_public_key(attestor_key_path, "attestor public key")
    require(requester_fingerprint != attestor_fingerprint, "requester and attestor keys must differ")
    output = output_path_outside_repository(arguments.output, "request output")
    commit, tree = validate_repository_clean()
    expiry_hours = unsigned_integer(arguments.expires_hours, "expiry hours", MAX_EXPIRY_HOURS)
    require(expiry_hours >= 1, "expiry must be at least one hour")
    nonce_hex = secrets.token_hex(32)
    issued = utc_now()
    expires = issued + dt.timedelta(hours=expiry_hours)
    source_commitment = machine_commitment(nonce_hex)
    pending_path = role_ledger("pending") / nonce_hex
    consumed_path = role_ledger("consumed") / nonce_hex
    require(not os.path.lexists(pending_path) and not os.path.lexists(consumed_path), "nonce unexpectedly exists in the source ledger")
    prompt_exact(
        "preparação do drill externo",
        (
            "Serão criados somente canários sintéticos e um source archive do HEAD limpo.",
            "O bundle deve ser levado a outra máquina junto com as chaves públicas por canais separados.",
            "Isto não autoriza credenciais reais e não prova separação física de hardware.",
        ),
        f"CRIAR DRILL EXTERNO {nonce_hex[:12].upper()}",
    )
    agent_socket = current_agent_socket()

    with tempfile.TemporaryDirectory(prefix="pvault-external-prepare-") as temporary:
        work = Path(temporary)
        work.chmod(0o700)
        source_archive = create_source_archive(work / SOURCE_ARCHIVE_NAME)
        source = safe_extract_source(source_archive, work / "source")
        helper = source / "tests" / "manual" / "external_restore_fixture.py"
        require(helper.is_file(), "source archive lacks the external fixture helper")
        home = work / "home"
        pvault = build_pvault(source, work / "build", home)
        fixture = work / "fixture"
        run_fixture_export(helper, source, pvault, fixture, nonce_hex, home)
        exact_directory_entries(fixture, FIXTURE_NAMES, "exported fixture")
        final_commit, final_tree = validate_repository_clean()
        require((final_commit, final_tree) == (commit, tree), "repository changed during request preparation")
        verify_source_archive_against_checkout(
            source_archive,
            work,
            "source-revalidated.tar",
        )

        payload: dict[str, bytes] = {SOURCE_ARCHIVE_NAME: source_archive}
        for name in FIXTURE_NAMES:
            payload[name] = read_file_descriptor_checked(
                fixture / name,
                label=f"exported fixture {name}",
                maximum=FILE_LIMITS[name],
            )
        manifest = [payload_manifest_entry(name, payload[name]) for name in PAYLOAD_NAMES]
        manifest_map = {entry["name"]: entry for entry in manifest}
        validate_fixture_summary(payload[FIXTURE_SUMMARY_NAME], nonce_hex=nonce_hex, payload=manifest_map)
        request = {
            "attestor_key_fingerprint": attestor_fingerprint,
            "classification": CLASSIFICATION,
            "expires_at": format_timestamp(expires),
            "fixture_summary_sha256": sha256_hex(payload[FIXTURE_SUMMARY_NAME]),
            "git_commit": commit,
            "git_tree": tree,
            "issued_at": format_timestamp(issued),
            "nonce_hex": nonce_hex,
            "payload": manifest,
            "requester_key_fingerprint": requester_fingerprint,
            "schema": REQUEST_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "source_archive_sha256": sha256_hex(source_archive),
            "source_machine_commitment": source_commitment,
            "synthetic_only": True,
        }
        request_bytes = canonical_json_bytes(request)
        request_path = work / REQUEST_JSON
        write_exclusive(request_path, request_bytes)
        signature_path = sign_document(
            request_path,
            key_reference=requester_key_path,
            public_key=requester_public,
            identity="pvault-requester",
            namespace=REQUEST_NAMESPACE,
            agent_socket=agent_socket,
        )
        signature_bytes = read_file_descriptor_checked(signature_path, label="request signature", maximum=MAX_SIGNATURE_BYTES)
        publish_request_directory(
            output,
            payload=payload,
            request_bytes=request_bytes,
            signature_bytes=signature_bytes,
        )
        ledger_document = {
            "attestor_key_fingerprint": attestor_fingerprint,
            "nonce_hex": nonce_hex,
            "request_sha256": sha256_hex(request_bytes),
            "request_signature_sha256": sha256_hex(signature_bytes),
            "requester_key_fingerprint": requester_fingerprint,
            "schema": "pvault.external-restore.pending",
            "schema_version": SCHEMA_VERSION,
            "source_machine_commitment": source_commitment,
        }
        try:
            write_ledger_entry("pending", nonce_hex, ledger_document)
        except BaseException:
            with contextlib.suppress(BaseException):
                remove_private_tree(output)
            raise

    print(f"PASS: request externo criado em {output}")
    print(f"Nonce: {nonce_hex}")
    print(f"Expira em: {format_timestamp(expires)}")
    print("Transfira o diretório preservando modos 0700/0600; as chaves públicas devem chegar fora do bundle.")


def validate_independent_checkout(request: Mapping[str, object]) -> tuple[str, str]:
    commit, tree = validate_repository_clean()
    require(commit == request["git_commit"], "runner checkout HEAD differs from the signed request commit")
    require(tree == request["git_tree"], "runner checkout tree differs from the signed request tree")
    return commit, tree


def derived_secret_canaries(nonce_hex: str) -> tuple[bytes, ...]:
    nonce = bytes.fromhex(nonce_hex)

    def token(label: bytes) -> str:
        return hashlib.sha256(
            b"pvault-external-restore-synthetic-v1\0" + label + b"\0" + nonce
        ).hexdigest()[:32]

    return (
        f"PVault-EXTERNAL-DRILL-ONLY-Master-{token(b'master-password')}!".encode("ascii"),
        f"PVault-EXTERNAL-DRILL-ONLY-Retained-{token(b'retained-password')}!".encode("ascii"),
        f"PVault-EXTERNAL-DRILL-ONLY-Mutation-{token(b'mutation-password')}!".encode("ascii"),
    )


def derived_plaintext_canaries(nonce_hex: str) -> tuple[bytes, ...]:
    nonce = bytes.fromhex(nonce_hex)

    def short_token(label: bytes) -> str:
        return hashlib.sha256(
            b"pvault-external-restore-synthetic-v1\0" + label + b"\0" + nonce
        ).hexdigest()[:16]

    retained = short_token(b"retained-record")
    mutation = short_token(b"mutation-record")
    return (
        *derived_secret_canaries(nonce_hex),
        f"PVault Synthetic External Retained {retained}".encode("ascii"),
        f"synthetic-retained-{retained}".encode("ascii"),
        f"PVault Synthetic External Mutation {mutation}".encode("ascii"),
        f"synthetic-mutation-{mutation}".encode("ascii"),
    )


def recovery_canary(data: bytes) -> bytes:
    values = [line for line in data.splitlines() if line.startswith(b"PV1R-")]
    require(len(values) == 1, "recovery payload does not contain exactly one PV1R value")
    return values[0]


def reserve_used_nonce(
    nonce_hex: str,
    *,
    request_hash: str,
    source_commitment: str,
    attestor_commitment: str,
) -> Path:
    path = role_ledger("used") / nonce_hex
    require(not os.path.lexists(path), "this nonce was already attempted on this attestor machine")
    return write_ledger_entry(
        "used",
        nonce_hex,
        {
            "attestor_machine_commitment": attestor_commitment,
            "nonce_hex": nonce_hex,
            "request_sha256": request_hash,
            "schema": "pvault.external-restore.used",
            "schema_version": SCHEMA_VERSION,
            "source_machine_commitment": source_commitment,
            "status": "consumed-before-exercise",
        },
    )


def run_command(arguments: argparse.Namespace) -> None:
    reject_automation()
    require(not os.environ.get("SSH_AUTH_SOCK") and not os.environ.get("SSH_AGENT_PID"), "run must start with SSH_AUTH_SOCK and SSH_AGENT_PID unset so tested code cannot reach the attestor key")
    requester_key_path = absolute_path(arguments.requester_pub)
    attestor_key_path = absolute_path(arguments.attestor_key)
    requester_public, requester_fingerprint = parse_ed25519_public_key(requester_key_path, "requester public key")
    attestor_public, attestor_fingerprint = parse_ed25519_public_key(attestor_key_path, "attestor public key")
    require(requester_fingerprint != attestor_fingerprint, "requester and attestor keys must differ")
    request_directory = absolute_path(arguments.request)
    result_output = output_path_outside_repository(arguments.result, "result output")
    request, _, payload, request_bytes, _ = read_request_directory(
        request_directory,
        requester_public_key=requester_public,
    )
    require(request["requester_key_fingerprint"] == requester_fingerprint, "trusted requester key does not match the request")
    require(request["attestor_key_fingerprint"] == attestor_fingerprint, "local attestor key does not match the key pinned by the requester")
    validate_independent_checkout(request)
    now = utc_now()
    issued = parse_timestamp(request["issued_at"], "request issue time")
    expires = parse_timestamp(request["expires_at"], "request expiry time")
    require(issued - CLOCK_SKEW <= now <= expires, "request is not currently valid (clock skew allowance is five minutes)")
    source_commitment = request["source_machine_commitment"]
    attestor_commitment = machine_commitment(request["nonce_hex"])
    require(source_commitment != attestor_commitment, "source and attestor machine commitments are equal")
    request_hash = sha256_hex(request_bytes)
    require(not os.path.lexists(role_ledger("used") / request["nonce_hex"]), "this nonce was already attempted on this machine")
    prompt_exact(
        "execução e declaração na segunda máquina",
        (
            "Confirme apenas se este é outro computador e outro armazenamento, não uma VM/container no host de origem.",
            "A chave B deve ser exclusiva desta máquina e não pode estar carregada em nenhum agente durante o exercício.",
            "O source assinado é tratado como confiável; este runner não isola código hostil executado sob o mesmo UID.",
            "A assinatura registra sua declaração; ela não prova fisicamente a separação das máquinas.",
        ),
        f"ATESTAR MAQUINA SEPARADA {request['nonce_hex'][:12].upper()}",
    )
    reserve_used_nonce(
        request["nonce_hex"],
        request_hash=request_hash,
        source_commitment=source_commitment,
        attestor_commitment=attestor_commitment,
    )

    with tempfile.TemporaryDirectory(prefix="pvault-external-run-") as temporary:
        work = Path(temporary)
        work.chmod(0o700)
        initial_snapshot = secure_file_snapshot(request_directory)
        verify_source_archive_against_checkout(payload[SOURCE_ARCHIVE_NAME], work)
        source = safe_extract_source(payload[SOURCE_ARCHIVE_NAME], work / "extracted")
        home = work / "home"
        pvault = build_pvault(source, work / "build", home)
        run_local_restore_drill(source, pvault, home)
        fixture = fixture_directory_from_payload(work, payload)
        fixture_result_path = work / "fixture-result.json"
        evidence = work / "evidence"
        helper = source / "tests" / "manual" / "external_restore_fixture.py"
        require(helper.is_file(), "validated source lacks the external fixture helper")
        run_fixture_exercise(
            helper,
            source,
            pvault,
            fixture,
            fixture_result_path,
            evidence,
            home,
        )
        exact_directory_entries(evidence, EVIDENCE_NAMES, "private restore evidence")
        pre_restore = read_file_descriptor_checked(
            evidence / "pre-restore.pvlt",
            label="pre-restore evidence",
            maximum=MAX_VAULT_BYTES,
        )
        final_restored = read_file_descriptor_checked(
            evidence / "final-restored.pvlt",
            label="final restored evidence",
            maximum=MAX_VAULT_BYTES,
        )
        fixture_result_bytes = read_file_descriptor_checked(
            fixture_result_path,
            label="fixture result JSON",
            maximum=MAX_JSON_BYTES,
        )
        fixture_hashes = validate_fixture_result(
            parse_canonical_json(fixture_result_bytes, "fixture result JSON"),
            request=request,
            payload=payload,
            pre_restore=pre_restore,
            final_restored=final_restored,
        )
        independent_pre_restore, independent_final = independent_restore_exercise(
            work,
            pvault=pvault,
            payload=payload,
            nonce_hex=request["nonce_hex"],
        )
        require(independent_pre_restore == pre_restore, "helper and independent pre-restore evidence differ")
        require(independent_final == final_restored, "helper and independent final evidence differ")
        final_snapshot = secure_file_snapshot(request_directory)
        require(initial_snapshot == final_snapshot, "signed request inputs changed during the exercise")
        validate_independent_checkout(request)
        verify_source_archive_against_checkout(
            payload[SOURCE_ARCHIVE_NAME],
            work,
            "source-regenerated-after-exercise.tar",
        )
        checks = {name: True for name in sorted(RESULT_CHECKS)}
        result_hashes = {
            "active_mutated_input_sha256": fixture_hashes["active_mutated_input_sha256"],
            "backup_input_sha256": fixture_hashes["backup_input_sha256"],
            "final_restored_sha256": fixture_hashes["final_restored_sha256"],
            "fixture_summary_sha256": sha256_hex(payload[FIXTURE_SUMMARY_NAME]),
            "pre_restore_sha256": fixture_hashes["pre_restore_sha256"],
            "source_archive_sha256": sha256_hex(payload[SOURCE_ARCHIVE_NAME]),
        }
        attested_at = utc_now()
        require(attested_at <= expires, "request expired while the external exercise was running")
        result = {
            "attested_at": format_timestamp(attested_at),
            "attestor_key_fingerprint": attestor_fingerprint,
            "attestor_machine_commitment": attestor_commitment,
            "checks": checks,
            "classification": CLASSIFICATION,
            "declaration": {
                "attestor_key_exclusive_to_second_machine": True,
                "machine_separation_is_operator_attested_only": True,
                "not_a_container_or_vm_on_the_source_host": True,
                "tested_source_is_trusted_not_hostile": True,
                "separate_machine_and_storage": True,
            },
            "fixture_result_sha256": sha256_hex(fixture_result_bytes),
            "git_commit": request["git_commit"],
            "git_tree": request["git_tree"],
            "hashes": result_hashes,
            "limitation": LIMITATION,
            "nonce_hex": request["nonce_hex"],
            "request_sha256": request_hash,
            "requester_key_fingerprint": requester_fingerprint,
            "schema": RESULT_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "source_machine_commitment": source_commitment,
            "synthetic_only": True,
        }
        result_bytes = canonical_json_bytes(result)
        secret_canaries = (*derived_secret_canaries(request["nonce_hex"]), recovery_canary(payload[RECOVERY_NAME]))
        for canary in secret_canaries:
            require(canary not in result_bytes, "synthetic secret appeared in the external result")

        # The tested code and all direct children have completed before the
        # dedicated signing agent exists.  The private evidence is no longer
        # needed by a subprocess; only this trusted launcher retains it.
        ensure_workspace_quiescent(work)
        result_path = work / RESULT_JSON
        write_exclusive(result_path, result_bytes)
        with dedicated_signing_agent(work) as agent_socket:
            prompt_exact(
                "assinatura isolada do resultado",
                (
                    "Todo build e exercício já terminou; um ssh-agent novo foi criado somente agora.",
                    "Em OUTRO terminal, carregue apenas a chave privada B com:",
                    f"SSH_AUTH_SOCK='{agent_socket}' ssh-add /caminho/da/chave-privada-B",
                ),
                f"ASSINAR RESULTADO EXTERNO {request['nonce_hex'][:12].upper()}",
            )
            signature_path = sign_document(
                result_path,
                key_reference=attestor_key_path,
                public_key=attestor_public,
                identity="pvault-attestor",
                namespace=RESULT_NAMESPACE,
                agent_socket=agent_socket,
            )
            signature_bytes = read_file_descriptor_checked(
                signature_path,
                label="result signature",
                maximum=MAX_SIGNATURE_BYTES,
            )
            require(utc_now() <= expires, "request expired while the external result was being signed")
        publish_signed_pair(
            result_output,
            document_name=RESULT_JSON,
            document_bytes=result_bytes,
            signature_name=RESULT_SIGNATURE,
            signature_bytes=signature_bytes,
            label="result output directory",
        )

    print(f"PASS: resultado externo assinado criado em {result_output}")
    print("Retorne somente result.json e result.json.sig à máquina de origem; nunca retorne vaults, recovery ou logs.")


def read_result_directory(
    result_directory: Path,
    *,
    attestor_public_key: str,
) -> tuple[dict[str, object], bytes, bytes]:
    exact_directory_entries(result_directory, {RESULT_JSON, RESULT_SIGNATURE}, "result directory")
    result_bytes = read_file_descriptor_checked(
        result_directory / RESULT_JSON,
        label="result JSON",
        maximum=MAX_JSON_BYTES,
    )
    signature_bytes = read_file_descriptor_checked(
        result_directory / RESULT_SIGNATURE,
        label="result signature",
        maximum=MAX_SIGNATURE_BYTES,
    )
    result = validate_result_document(parse_canonical_json(result_bytes, "result JSON"))
    verify_signature_bytes(
        result_bytes,
        signature_bytes,
        public_key=attestor_public_key,
        identity="pvault-attestor",
        namespace=RESULT_NAMESPACE,
    )
    return result, result_bytes, signature_bytes


def validate_pending_ledger(
    value: dict[str, object],
    *,
    request: Mapping[str, object],
    request_bytes: bytes,
    request_signature_bytes: bytes,
) -> None:
    ledger = exact_object(
        value,
        {
            "attestor_key_fingerprint",
            "nonce_hex",
            "request_sha256",
            "request_signature_sha256",
            "requester_key_fingerprint",
            "schema",
            "schema_version",
            "source_machine_commitment",
        },
        "pending ledger",
    )
    require(ledger["schema"] == "pvault.external-restore.pending", "pending ledger schema is invalid")
    require(ledger["schema_version"] == SCHEMA_VERSION, "pending ledger version is invalid")
    expected = {
        "attestor_key_fingerprint": request["attestor_key_fingerprint"],
        "nonce_hex": request["nonce_hex"],
        "request_sha256": sha256_hex(request_bytes),
        "request_signature_sha256": sha256_hex(request_signature_bytes),
        "requester_key_fingerprint": request["requester_key_fingerprint"],
        "source_machine_commitment": request["source_machine_commitment"],
    }
    for name, expected_value in expected.items():
        require(ledger[name] == expected_value, f"pending ledger mismatch: {name}")


def validate_result_against_request(
    result: Mapping[str, object],
    *,
    request: Mapping[str, object],
    request_bytes: bytes,
    payload: Mapping[str, bytes],
    require_current: bool = True,
) -> None:
    bindings = {
        "nonce_hex": request["nonce_hex"],
        "request_sha256": sha256_hex(request_bytes),
        "git_commit": request["git_commit"],
        "git_tree": request["git_tree"],
        "source_machine_commitment": request["source_machine_commitment"],
        "requester_key_fingerprint": request["requester_key_fingerprint"],
        "attestor_key_fingerprint": request["attestor_key_fingerprint"],
    }
    for name, expected in bindings.items():
        require(result[name] == expected, f"result/request binding mismatch: {name}")
    expected_hashes = {
        "active_mutated_input_sha256": sha256_hex(payload[ACTIVE_NAME]),
        "backup_input_sha256": sha256_hex(payload[BACKUP_NAME]),
        "final_restored_sha256": sha256_hex(payload[BACKUP_NAME]),
        "fixture_summary_sha256": sha256_hex(payload[FIXTURE_SUMMARY_NAME]),
        "pre_restore_sha256": sha256_hex(payload[ACTIVE_NAME]),
        "source_archive_sha256": sha256_hex(payload[SOURCE_ARCHIVE_NAME]),
    }
    require(result["hashes"] == expected_hashes, "result hashes do not bind the source-machine bytes")
    issued = parse_timestamp(request["issued_at"], "request issue time")
    expires = parse_timestamp(request["expires_at"], "request expiry time")
    attested = parse_timestamp(result["attested_at"], "result attestation time")
    now = utc_now()
    require(issued - CLOCK_SKEW <= attested <= expires, "attestation timestamp falls outside the request validity window")
    require(attested <= now + CLOCK_SKEW, "attestation timestamp is implausibly far in the future")
    if require_current:
        require(now <= expires, "request expired before source-machine acceptance")


def validate_receipt_against_artifacts(
    receipt_value: dict[str, object],
    *,
    request: Mapping[str, object],
    request_bytes: bytes,
    request_signature_bytes: bytes,
    result: Mapping[str, object],
    result_bytes: bytes,
    result_signature_bytes: bytes,
    requester_fingerprint: str,
    attestor_fingerprint: str,
) -> dict[str, object]:
    receipt = exact_object(receipt_value, RECEIPT_KEYS, "external restore receipt")
    expected = {
        "attestor_key_fingerprint": attestor_fingerprint,
        "attestor_machine_commitment": result["attestor_machine_commitment"],
        "classification": CLASSIFICATION,
        "decision": "accepted",
        "limitation": LIMITATION,
        "nonce_hex": request["nonce_hex"],
        "request_sha256": sha256_hex(request_bytes),
        "request_signature_sha256": sha256_hex(request_signature_bytes),
        "requester_key_fingerprint": requester_fingerprint,
        "result_sha256": sha256_hex(result_bytes),
        "result_signature_sha256": sha256_hex(result_signature_bytes),
        "schema": RECEIPT_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "source_machine_commitment": request["source_machine_commitment"],
        "synthetic_only": True,
    }
    for name, expected_value in expected.items():
        require(receipt[name] == expected_value, f"receipt/artifact binding mismatch: {name}")
    accepted = parse_timestamp(receipt["accepted_at"], "receipt acceptance time")
    attested = parse_timestamp(result["attested_at"], "result attestation time")
    issued = parse_timestamp(request["issued_at"], "request issue time")
    expires = parse_timestamp(request["expires_at"], "request expiry time")
    require(issued - CLOCK_SKEW <= attested <= accepted + CLOCK_SKEW, "receipt time precedes the attestation")
    require(accepted <= expires, "receipt was accepted after request expiry")
    return receipt


def read_consumed_receipt(
    consumed_path: Path,
    *,
    request: Mapping[str, object],
    request_bytes: bytes,
    request_signature_bytes: bytes,
    result: Mapping[str, object],
    result_bytes: bytes,
    result_signature_bytes: bytes,
    requester_fingerprint: str,
    attestor_fingerprint: str,
    requester_public: str,
) -> tuple[bytes, bytes]:
    exact_directory_entries(
        consumed_path,
        {"ledger.json", RECEIPT_JSON, RECEIPT_SIGNATURE},
        "consumed ledger entry",
    )
    ledger_bytes = read_file_descriptor_checked(
        consumed_path / "ledger.json",
        label="consumed ledger document",
        maximum=MAX_JSON_BYTES,
    )
    validate_pending_ledger(
        parse_canonical_json(ledger_bytes, "consumed ledger document"),
        request=request,
        request_bytes=request_bytes,
        request_signature_bytes=request_signature_bytes,
    )
    receipt_bytes = read_file_descriptor_checked(
        consumed_path / RECEIPT_JSON,
        label="consumed receipt JSON",
        maximum=MAX_JSON_BYTES,
    )
    receipt_signature_bytes = read_file_descriptor_checked(
        consumed_path / RECEIPT_SIGNATURE,
        label="consumed receipt signature",
        maximum=MAX_SIGNATURE_BYTES,
    )
    validate_receipt_against_artifacts(
        parse_canonical_json(receipt_bytes, "consumed receipt JSON"),
        request=request,
        request_bytes=request_bytes,
        request_signature_bytes=request_signature_bytes,
        result=result,
        result_bytes=result_bytes,
        result_signature_bytes=result_signature_bytes,
        requester_fingerprint=requester_fingerprint,
        attestor_fingerprint=attestor_fingerprint,
    )
    verify_signature_bytes(
        receipt_bytes,
        receipt_signature_bytes,
        public_key=requester_public,
        identity="pvault-requester",
        namespace=RECEIPT_NAMESPACE,
    )
    return receipt_bytes, receipt_signature_bytes


def check_command(arguments: argparse.Namespace) -> None:
    reject_automation()
    requester_key_path = absolute_path(arguments.requester_key)
    attestor_key_path = absolute_path(arguments.attestor_pub)
    requester_public, requester_fingerprint = parse_ed25519_public_key(requester_key_path, "requester public key")
    attestor_public, attestor_fingerprint = parse_ed25519_public_key(attestor_key_path, "attestor public key")
    require(requester_fingerprint != attestor_fingerprint, "requester and attestor keys must differ")
    request_directory = absolute_path(arguments.request)
    result_directory = absolute_path(arguments.result)
    receipt_output = output_path_outside_repository(
        arguments.receipt if arguments.receipt else str(result_directory) + ".receipt",
        "receipt output",
        allow_existing=True,
    )
    request, _, payload, request_bytes, request_signature_bytes = read_request_directory(
        request_directory,
        requester_public_key=requester_public,
    )
    require(request["requester_key_fingerprint"] == requester_fingerprint, "requester key does not match request")
    require(request["attestor_key_fingerprint"] == attestor_fingerprint, "attestor key does not match request pin")
    result, result_bytes, result_signature_bytes = read_result_directory(
        result_directory,
        attestor_public_key=attestor_public,
    )
    consumed_parent = role_ledger("consumed")
    consumed_path = consumed_parent / request["nonce_hex"]
    pending_candidate = role_ledger("pending") / request["nonce_hex"]
    if os.path.lexists(consumed_path):
        validate_result_against_request(
            result,
            request=request,
            request_bytes=request_bytes,
            payload=payload,
            require_current=False,
        )
        receipt_bytes, receipt_signature_bytes = read_consumed_receipt(
            consumed_path,
            request=request,
            request_bytes=request_bytes,
            request_signature_bytes=request_signature_bytes,
            result=result,
            result_bytes=result_bytes,
            result_signature_bytes=result_signature_bytes,
            requester_fingerprint=requester_fingerprint,
            attestor_fingerprint=attestor_fingerprint,
            requester_public=requester_public,
        )
        publish_or_validate_signed_pair(
            receipt_output,
            document_name=RECEIPT_JSON,
            document_bytes=receipt_bytes,
            signature_name=RECEIPT_SIGNATURE,
            signature_bytes=receipt_signature_bytes,
            label="receipt output directory",
        )
        if os.path.lexists(pending_candidate):
            pending_path, pending = read_ledger_entry("pending", request["nonce_hex"])
            validate_pending_ledger(
                pending,
                request=request,
                request_bytes=request_bytes,
                request_signature_bytes=request_signature_bytes,
            )
            remove_private_tree(pending_path)
            fsync_directory(pending_path.parent)
        print(f"PASS: receipt já consumido foi validado/recuperado em {receipt_output}")
        print(f"Ledger consumido: {consumed_path}")
        return

    validate_result_against_request(result, request=request, request_bytes=request_bytes, payload=payload)
    pending_path, pending = read_ledger_entry("pending", request["nonce_hex"])
    validate_pending_ledger(
        pending,
        request=request,
        request_bytes=request_bytes,
        request_signature_bytes=request_signature_bytes,
    )
    prompt_exact(
        "aceitação na máquina de origem",
        (
            "As assinaturas, hashes, timestamps, commitments e todos os checks foram validados.",
            "A aceitação registra uma declaração operacional, não prova separação física nem autoriza senhas reais.",
            "O nonce será consumido de forma permanente após a assinatura do receipt.",
        ),
        f"ACEITAR RESTAURACAO EXTERNA {request['nonce_hex'][:12].upper()}",
    )
    expires = parse_timestamp(request["expires_at"], "request expiry time")
    require(utc_now() <= expires, "request expired while awaiting source-machine acceptance")
    agent_socket = current_agent_socket()
    accepted_at = utc_now()
    receipt = {
        "accepted_at": format_timestamp(accepted_at),
        "attestor_key_fingerprint": attestor_fingerprint,
        "attestor_machine_commitment": result["attestor_machine_commitment"],
        "classification": CLASSIFICATION,
        "decision": "accepted",
        "limitation": LIMITATION,
        "nonce_hex": request["nonce_hex"],
        "request_sha256": sha256_hex(request_bytes),
        "request_signature_sha256": sha256_hex(request_signature_bytes),
        "requester_key_fingerprint": requester_fingerprint,
        "result_sha256": sha256_hex(result_bytes),
        "result_signature_sha256": sha256_hex(result_signature_bytes),
        "schema": RECEIPT_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "source_machine_commitment": request["source_machine_commitment"],
        "synthetic_only": True,
    }
    receipt_bytes = canonical_json_bytes(receipt)
    with tempfile.TemporaryDirectory(prefix="pvault-external-receipt-") as temporary:
        work = Path(temporary)
        work.chmod(0o700)
        receipt_path = work / RECEIPT_JSON
        write_exclusive(receipt_path, receipt_bytes)
        signature_path = sign_document(
            receipt_path,
            key_reference=requester_key_path,
            public_key=requester_public,
            identity="pvault-requester",
            namespace=RECEIPT_NAMESPACE,
            agent_socket=agent_socket,
        )
        receipt_signature_bytes = read_file_descriptor_checked(
            signature_path,
            label="receipt signature",
            maximum=MAX_SIGNATURE_BYTES,
        )
        require(utc_now() <= expires, "request expired while the receipt was being signed")

        # Build a complete consumed-state directory beside its final location,
        # then publish it with one atomic rename. Pending remains untouched
        # until the durable consumed state and public receipt both exist.
        staging = consumed_parent / f".{request['nonce_hex']}.{secrets.token_hex(8)}.staging"
        create_private_directory(staging, "consumed receipt staging directory")
        try:
            write_exclusive(staging / "ledger.json", canonical_json_bytes(pending))
            write_exclusive(staging / RECEIPT_JSON, receipt_bytes)
            write_exclusive(staging / RECEIPT_SIGNATURE, receipt_signature_bytes)
            fsync_directory(staging)
            require(utc_now() <= expires, "request expired before durable nonce consumption")
            require(not os.path.lexists(consumed_path), "consumed ledger entry appeared concurrently")
            os.rename(staging, consumed_path)
            fsync_directory(consumed_parent)
        except OSError as error:
            with contextlib.suppress(BaseException):
                remove_private_tree(staging)
            raise ProtocolError("could not atomically publish the consumed receipt state") from error
        except BaseException:
            with contextlib.suppress(BaseException):
                remove_private_tree(staging)
            raise
        publish_or_validate_signed_pair(
            receipt_output,
            document_name=RECEIPT_JSON,
            document_bytes=receipt_bytes,
            signature_name=RECEIPT_SIGNATURE,
            signature_bytes=receipt_signature_bytes,
            label="receipt output directory",
        )
        remove_private_tree(pending_path)
        fsync_directory(pending_path.parent)

    print(f"PASS: receipt de restauração externa aceito e assinado em {receipt_output}")
    print(f"Ledger consumido: {role_ledger('consumed') / request['nonce_hex']}")


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare, run, or accept a signed synthetic external-machine "
            "PVault restore attestation. This manual protocol never proves "
            "physical machine separation."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="create and sign a synthetic request on machine A")
    prepare.add_argument("--output", required=True, help="new private request directory outside the repository")
    prepare.add_argument("--requester-key", required=True, help="requester Ed25519 public key loaded in ssh-agent")
    prepare.add_argument("--attestor-pub", required=True, help="attestor Ed25519 public key obtained out of band")
    prepare.add_argument(
        "--expires-hours",
        type=int,
        default=DEFAULT_EXPIRY_HOURS,
        help=f"request lifetime from 1 to {MAX_EXPIRY_HOURS} hours (default: {DEFAULT_EXPIRY_HOURS})",
    )

    run = subparsers.add_parser("run", help="verify and exercise a request on machine B")
    run.add_argument("--request", required=True, help="transferred private request directory")
    run.add_argument("--result", required=True, help="new private result directory outside the repository")
    run.add_argument("--requester-pub", required=True, help="requester Ed25519 public key obtained out of band")
    run.add_argument("--attestor-key", required=True, help="attestor Ed25519 public key; private key is loaded only after tests")

    check = subparsers.add_parser("check", help="verify a result and countersign a receipt on machine A")
    check.add_argument("--request", required=True, help="original private request directory")
    check.add_argument("--result", required=True, help="returned private result directory")
    check.add_argument("--requester-key", required=True, help="requester Ed25519 public key loaded in ssh-agent")
    check.add_argument("--attestor-pub", required=True, help="attestor Ed25519 public key obtained out of band")
    check.add_argument("--receipt", help="new receipt directory (default: RESULT.receipt)")
    return parser


def main() -> int:
    os.umask(0o077)
    arguments = argument_parser().parse_args()
    try:
        if arguments.command == "prepare":
            prepare_command(arguments)
        elif arguments.command == "run":
            run_command(arguments)
        elif arguments.command == "check":
            check_command(arguments)
        else:  # pragma: no cover - argparse enforces this
            fail("unsupported protocol command")
    except (ProtocolError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        print(f"external-restore protocol: FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
