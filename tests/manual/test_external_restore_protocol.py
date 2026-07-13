#!/usr/bin/env python3
"""Pure parser/filesystem tests; these never satisfy the external-host gate."""

from __future__ import annotations

import base64
import hashlib
import io
import os
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
import external_restore_protocol as protocol  # noqa: E402


def ssh_string(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


class CanonicalJsonTests(unittest.TestCase):
    def test_round_trip_is_compact_sorted_ascii_with_lf(self) -> None:
        value = {"z": [True, 4], "a": "ascii"}
        data = protocol.canonical_json_bytes(value)
        self.assertEqual(data, b'{"a":"ascii","z":[true,4]}\n')
        self.assertEqual(protocol.parse_canonical_json(data, "test"), value)

    def test_rejects_duplicate_noncanonical_float_null_and_unicode(self) -> None:
        invalid = (
            b'{"a":1,"a":1}\n',
            b'{ "a":1}\n',
            b'{"a":1.0}\n',
            b'{"a":null}\n',
            '{"a":"é"}\n'.encode(),
            b'{"a":-1}\n',
        )
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(protocol.ProtocolError):
                protocol.parse_canonical_json(data, "invalid test JSON")

    def test_bool_never_passes_unsigned_integer(self) -> None:
        with self.assertRaises(protocol.ProtocolError):
            protocol.unsigned_integer(True, "boolean", 2)


class PublicKeyTests(unittest.TestCase):
    def test_parses_one_canonical_ed25519_key(self) -> None:
        blob = ssh_string(b"ssh-ed25519") + ssh_string(bytes(range(32)))
        line = b"ssh-ed25519 " + base64.b64encode(blob) + b" test-comment\n"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "key.pub"
            path.write_bytes(line)
            path.chmod(0o600)
            normalized, fingerprint = protocol.parse_ed25519_public_key(path, "test key")
        self.assertEqual(normalized, line.decode().split(" test-comment", 1)[0])
        expected = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        self.assertEqual(fingerprint, f"SHA256:{expected}")

    def test_rejects_multiple_keys_and_hardlinks(self) -> None:
        blob = ssh_string(b"ssh-ed25519") + ssh_string(bytes(range(32)))
        line = b"ssh-ed25519 " + base64.b64encode(blob) + b"\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            multiple = root / "multiple.pub"
            multiple.write_bytes(line + line)
            multiple.chmod(0o600)
            with self.assertRaises(protocol.ProtocolError):
                protocol.parse_ed25519_public_key(multiple, "multiple keys")
            linked = root / "linked.pub"
            linked.write_bytes(line)
            linked.chmod(0o600)
            os.link(linked, root / "second-link")
            with self.assertRaises(protocol.ProtocolError):
                protocol.parse_ed25519_public_key(linked, "linked key")


class SignatureEnvelopeTests(unittest.TestCase):
    def canonical_envelope(self) -> bytes:
        encoded = base64.b64encode(b"SSHSIG" + bytes(range(128))).decode()
        lines = [encoded[index : index + 70] for index in range(0, len(encoded), 70)]
        return (
            "-----BEGIN SSH SIGNATURE-----\n"
            + "\n".join(lines)
            + "\n-----END SSH SIGNATURE-----\n"
        ).encode()

    def test_accepts_one_canonical_envelope_only(self) -> None:
        envelope = self.canonical_envelope()
        protocol.validate_ssh_signature_envelope(envelope)
        for modified in (
            envelope + b"TRAILING\n",
            b"PREFIX\n" + envelope,
            envelope + envelope,
            envelope.replace(b"\n", b"\r\n"),
            envelope.replace(b"\n", b"\n\n", 1),
        ):
            with self.subTest(modified=modified), self.assertRaises(protocol.ProtocolError):
                protocol.validate_ssh_signature_envelope(modified)


class DocumentTests(unittest.TestCase):
    def request(self) -> tuple[dict[str, object], dict[str, bytes]]:
        payload = {name: (name + " synthetic").encode() for name in protocol.PAYLOAD_NAMES}
        entries = [protocol.payload_manifest_entry(name, payload[name]) for name in protocol.PAYLOAD_NAMES]
        request = {
            "attestor_key_fingerprint": "SHA256:" + "B" * 43,
            "classification": protocol.CLASSIFICATION,
            "expires_at": "2026-07-16T00:00:00Z",
            "fixture_summary_sha256": hashlib.sha256(payload[protocol.FIXTURE_SUMMARY_NAME]).hexdigest(),
            "git_commit": "1" * 40,
            "git_tree": "2" * 40,
            "issued_at": "2026-07-13T00:00:00Z",
            "nonce_hex": "3" * 64,
            "payload": entries,
            "requester_key_fingerprint": "SHA256:" + "A" * 43,
            "schema": protocol.REQUEST_SCHEMA,
            "schema_version": 1,
            "source_archive_sha256": hashlib.sha256(payload[protocol.SOURCE_ARCHIVE_NAME]).hexdigest(),
            "source_machine_commitment": "4" * 64,
            "synthetic_only": True,
        }
        return request, payload

    def test_request_schema_is_closed(self) -> None:
        request, _ = self.request()
        validated, manifest = protocol.validate_request_document(request)
        self.assertIs(validated, request)
        self.assertEqual(set(manifest), set(protocol.PAYLOAD_NAMES))
        request["unknown"] = True
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate_request_document(request)

    def test_request_rejects_same_role_key(self) -> None:
        request, _ = self.request()
        request["attestor_key_fingerprint"] = request["requester_key_fingerprint"]
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate_request_document(request)

    def test_request_rejects_nonstandard_git_object_id_length(self) -> None:
        request, _ = self.request()
        request["git_commit"] = "1" * 41
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate_request_document(request)

    def test_result_requires_every_true_check(self) -> None:
        result = {
            "attested_at": "2026-07-13T01:00:00Z",
            "attestor_key_fingerprint": "SHA256:" + "B" * 43,
            "attestor_machine_commitment": "5" * 64,
            "checks": {name: True for name in protocol.RESULT_CHECKS},
            "classification": protocol.CLASSIFICATION,
            "declaration": {name: True for name in protocol.DECLARATION_KEYS},
            "fixture_result_sha256": "6" * 64,
            "git_commit": "1" * 40,
            "git_tree": "2" * 40,
            "hashes": {name: "7" * 64 for name in protocol.RESULT_HASH_KEYS},
            "limitation": protocol.LIMITATION,
            "nonce_hex": "3" * 64,
            "request_sha256": "8" * 64,
            "requester_key_fingerprint": "SHA256:" + "A" * 43,
            "schema": protocol.RESULT_SCHEMA,
            "schema_version": 1,
            "source_machine_commitment": "4" * 64,
            "synthetic_only": True,
        }
        protocol.validate_result_document(result)
        result["checks"]["build"] = False
        with self.assertRaises(protocol.ProtocolError):
            protocol.validate_result_document(result)


class ArchiveTests(unittest.TestCase):
    def archive(self, members: list[tuple[tarfile.TarInfo, bytes]]) -> bytes:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for member, contents in members:
                archive.addfile(member, io.BytesIO(contents) if member.isfile() else None)
        return stream.getvalue()

    def regular(self, name: str, contents: bytes) -> tuple[tarfile.TarInfo, bytes]:
        member = tarfile.TarInfo(name)
        member.size = len(contents)
        member.mode = 0o644
        return member, contents

    def test_extracts_only_regular_prefixed_source(self) -> None:
        data = self.archive([self.regular("pvault-source/CMakeLists.txt", b"project(test)\n")])
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "extract"
            root = protocol.safe_extract_source(data, destination)
            self.assertEqual((root / "CMakeLists.txt").read_bytes(), b"project(test)\n")
            self.assertEqual(stat.S_IMODE((root / "CMakeLists.txt").stat().st_mode), 0o600)

    def test_rejects_traversal_and_symlink(self) -> None:
        traversal = self.archive([self.regular("pvault-source/../escape", b"bad")])
        symlink = tarfile.TarInfo("pvault-source/link")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "/tmp/target"
        linked = self.archive([(symlink, b"")])
        for index, data in enumerate((traversal, linked)):
            with tempfile.TemporaryDirectory() as temporary:
                destination = Path(temporary) / f"extract-{index}"
                with self.assertRaises(protocol.ProtocolError):
                    protocol.safe_extract_source(data, destination)
                self.assertFalse(destination.exists())


class CommitmentTests(unittest.TestCase):
    def test_commitment_is_nonce_salted_and_deterministic(self) -> None:
        machine_id = b"0123456789abcdef0123456789abcdef\n"
        first = protocol.machine_commitment("00" * 32, machine_id)
        second = protocol.machine_commitment("01" * 32, machine_id)
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertNotEqual(first, second)
        self.assertEqual(first, protocol.machine_commitment("00" * 32, machine_id))


class CommandCaptureTests(unittest.TestCase):
    def test_captures_small_output_and_rejects_output_flood(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = protocol.minimal_environment(home=root)
            output = protocol.command_output(
                ["/usr/bin/python3", "-c", "print('bounded')"],
                cwd=root,
                environment=environment,
                label="small command",
            )
            self.assertEqual(output, b"bounded\n")
            with self.assertRaises(protocol.ProtocolError):
                protocol.command_output(
                    [
                        "/usr/bin/python3",
                        "-c",
                        f"import os; os.write(1, b'x' * {protocol.MAX_COMMAND_OUTPUT_BYTES + 1})",
                    ],
                    cwd=root,
                    environment=environment,
                    label="output flood",
                )


class AtomicPublicationTests(unittest.TestCase):
    def test_signed_pair_is_atomic_and_idempotently_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            destination = root / "receipt"
            protocol.publish_signed_pair(
                destination,
                document_name="receipt.json",
                document_bytes=b"{}\n",
                signature_name="receipt.json.sig",
                signature_bytes=b"synthetic-signature",
                label="test receipt",
            )
            self.assertEqual({path.name for path in destination.iterdir()}, {"receipt.json", "receipt.json.sig"})
            protocol.publish_or_validate_signed_pair(
                destination,
                document_name="receipt.json",
                document_bytes=b"{}\n",
                signature_name="receipt.json.sig",
                signature_bytes=b"synthetic-signature",
                label="test receipt",
            )
            with self.assertRaises(protocol.ProtocolError):
                protocol.publish_or_validate_signed_pair(
                    destination,
                    document_name="receipt.json",
                    document_bytes=b"different\n",
                    signature_name="receipt.json.sig",
                    signature_bytes=b"synthetic-signature",
                    label="test receipt",
                )

    def test_partial_existing_output_is_never_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            destination = root / "partial"
            destination.mkdir(mode=0o700)
            document = destination / "receipt.json"
            document.write_bytes(b"{}\n")
            document.chmod(0o600)
            with self.assertRaises(protocol.ProtocolError):
                protocol.publish_or_validate_signed_pair(
                    destination,
                    document_name="receipt.json",
                    document_bytes=b"{}\n",
                    signature_name="receipt.json.sig",
                    signature_bytes=b"synthetic-signature",
                    label="partial receipt",
                )


if __name__ == "__main__":
    unittest.main()
