#!/usr/bin/env python3
"""Generate and verify the independent synthetic PVault v1.0 vector.

This module intentionally does not import, execute, or bind to PVault code.
It implements the wire layout and deterministic CBOR profile directly from
docs/FORMAT.md, and uses ctypes only for the cryptographic primitives exported
by the system libsodium.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import Any, Callable, NoReturn


GENERATOR = Path(__file__).resolve()
DIRECTORY = GENERATOR.parent
REPOSITORY = DIRECTORY.parents[1]
FORMAT_CONTRACT = REPOSITORY / "docs" / "FORMAT.md"
FIXTURE = DIRECTORY / "pvault-v1-synthetic.bin"
MANIFEST = DIRECTORY / "pvault-v1-synthetic.json"

MAGIC = b"PVLT\x0d\x0a\x1a\x0a"
HEADER_LENGTH = 252
BODY_BLOCK_SIZE = 4096
AEAD_TAG_LENGTH = 16
FORMAT_MAJOR = 1
FORMAT_MINOR = 0
KDF_ID_ARGON2ID13 = 1
AEAD_ID_XCHACHA20POLY1305 = 1
SLOT_COUNT = 2
PASSWORD_OPSLIMIT = 3
PASSWORD_MEMLIMIT = 256 * 1024 * 1024

# Every value below is public test material. It must never be reused for a real
# vault, credential, recovery code, random seed, or cryptographic key.
SYNTHETIC_PASSWORD = b"pvault-v1-synthetic-password"
SYNTHETIC_VAULT_ID = bytes(range(0x10, 0x20))
SYNTHETIC_RECOVERY_KEY = bytes(range(0x20, 0x40))
SYNTHETIC_VMK = bytes(range(0x40, 0x60))
SYNTHETIC_PASSWORD_SALT = bytes(range(0x60, 0x70))
SYNTHETIC_PASSWORD_NONCE = bytes(range(0x70, 0x88))
SYNTHETIC_RECOVERY_NONCE = bytes(range(0x88, 0xA0))
SYNTHETIC_BODY_NONCE = bytes(range(0xA0, 0xB8))
SYNTHETIC_DEVICE_ID = bytes(range(0xB0, 0xC0))
SYNTHETIC_RECORD_ID = bytes(range(0xC0, 0xD0))

RECOVERY_CONTEXT = b"PVRECV01"
BODY_CONTEXT = b"PVBODY01"
CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class VectorError(RuntimeError):
    """A deterministic vector or dependency did not satisfy the contract."""


def fail(message: str) -> NoReturn:
    raise VectorError(message)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cbor_head(major: int, value: int) -> bytes:
    if major < 0 or major > 7 or value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        fail("CBOR head value is outside the supported range")
    prefix = major << 5
    if value < 24:
        return bytes((prefix | value,))
    if value <= 0xFF:
        return bytes((prefix | 24, value))
    if value <= 0xFFFF:
        return bytes((prefix | 25,)) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes((prefix | 26,)) + struct.pack(">I", value)
    return bytes((prefix | 27,)) + struct.pack(">Q", value)


def cbor_uint(value: int) -> bytes:
    return cbor_head(0, value)


def cbor_bytes(value: bytes) -> bytes:
    return cbor_head(2, len(value)) + value


def cbor_text(value: str) -> bytes:
    encoded = value.encode("utf-8", "strict")
    return cbor_head(3, len(encoded)) + encoded


def cbor_array(items: list[bytes]) -> bytes:
    return cbor_head(4, len(items)) + b"".join(items)


def cbor_map(items: list[tuple[int, bytes]]) -> bytes:
    if any(key < 0 for key, _ in items):
        fail("PVault map keys must be unsigned")
    keys = [key for key, _ in items]
    if keys != sorted(set(keys)):
        fail("PVault map keys must be unique and increasing")
    return cbor_head(5, len(items)) + b"".join(
        cbor_uint(key) + encoded for key, encoded in items
    )


def expected_payload() -> dict[int, Any]:
    return {
        0: 1,
        1: 7,
        2: SYNTHETIC_DEVICE_ID,
        3: 1_700_000_000_123,
        4: 1_700_001_234_567,
        5: [
            {
                0: SYNTHETIC_RECORD_ID,
                1: 3,
                2: 1_700_000_100_000,
                3: 1_700_000_200_000,
                4: 2,
                5: "Synthetic fixture",
                6: "alice@example.invalid",
                7: b"\x00synthetic-password\xff",
                8: ["https://example.invalid/login"],
                9: "Deterministic compatibility fixture; no real secret.",
                10: ["synthetic", "compat-v1"],
                11: [
                    {0: "api-token", 1: b"synthetic-token-\x00\xff", 2: 1},
                    {0: "account", 1: b"fixture-0001", 2: 0},
                ],
            }
        ],
    }


def encode_payload() -> bytes:
    record = cbor_map(
        [
            (0, cbor_bytes(SYNTHETIC_RECORD_ID)),
            (1, cbor_uint(3)),
            (2, cbor_uint(1_700_000_100_000)),
            (3, cbor_uint(1_700_000_200_000)),
            (4, cbor_uint(2)),
            (5, cbor_text("Synthetic fixture")),
            (6, cbor_text("alice@example.invalid")),
            (7, cbor_bytes(b"\x00synthetic-password\xff")),
            (8, cbor_array([cbor_text("https://example.invalid/login")])),
            (
                9,
                cbor_text("Deterministic compatibility fixture; no real secret."),
            ),
            (10, cbor_array([cbor_text("synthetic"), cbor_text("compat-v1")])),
            (
                11,
                cbor_array(
                    [
                        cbor_map(
                            [
                                (0, cbor_text("api-token")),
                                (1, cbor_bytes(b"synthetic-token-\x00\xff")),
                                (2, cbor_uint(1)),
                            ]
                        ),
                        cbor_map(
                            [
                                (0, cbor_text("account")),
                                (1, cbor_bytes(b"fixture-0001")),
                                (2, cbor_uint(0)),
                            ]
                        ),
                    ]
                ),
            ),
        ]
    )
    return cbor_map(
        [
            (0, cbor_uint(1)),
            (1, cbor_uint(7)),
            (2, cbor_bytes(SYNTHETIC_DEVICE_ID)),
            (3, cbor_uint(1_700_000_000_123)),
            (4, cbor_uint(1_700_001_234_567)),
            (5, cbor_array([record])),
        ]
    )


class CborReader:
    """Strict decoder for the subset used by the independent fixture."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def take(self, length: int) -> bytes:
        if length < 0 or self.position + length > len(self.data):
            fail("truncated CBOR item")
        result = self.data[self.position : self.position + length]
        self.position += length
        return result

    def head(self) -> tuple[int, int]:
        initial = self.take(1)[0]
        major = initial >> 5
        additional = initial & 0x1F
        if additional < 24:
            return major, additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        if additional not in widths:
            fail("indefinite or reserved CBOR length")
        width = widths[additional]
        value = int.from_bytes(self.take(width), "big")
        if (
            (width == 1 and value < 24)
            or (width == 2 and value <= 0xFF)
            or (width == 4 and value <= 0xFFFF)
            or (width == 8 and value <= 0xFFFFFFFF)
        ):
            fail("non-minimal CBOR integer or length")
        return major, value

    def item(self, depth: int = 0) -> Any:
        if depth > 16:
            fail("CBOR nesting exceeds the fixture limit")
        major, value = self.head()
        if major == 0:
            return value
        if major == 2:
            return self.take(value)
        if major == 3:
            try:
                return self.take(value).decode("utf-8", "strict")
            except UnicodeDecodeError as error:
                raise VectorError("invalid UTF-8 in CBOR text") from error
        if major == 4:
            return [self.item(depth + 1) for _ in range(value)]
        if major == 5:
            result: dict[int, Any] = {}
            previous = -1
            for _ in range(value):
                key = self.item(depth + 1)
                if not isinstance(key, int) or isinstance(key, bool):
                    fail("PVault fixture map key is not unsigned")
                if key <= previous:
                    fail("PVault fixture map keys are not strictly increasing")
                previous = key
                result[key] = self.item(depth + 1)
            return result
        fail(f"unsupported CBOR major type {major}")

    def complete_item(self) -> Any:
        result = self.item()
        if self.position != len(self.data):
            fail("trailing bytes after the deterministic CBOR payload")
        return result


def ctypes_buffer(data: bytes) -> ctypes.Array[ctypes.c_ubyte]:
    if not data:
        fail("empty ctypes input is not used by this vector")
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


class Sodium:
    """Small ctypes binding for only the primitives required by format v1.0."""

    def __init__(self) -> None:
        library_name = ctypes.util.find_library("sodium")
        if library_name is None:
            fail("could not locate the system libsodium")
        self.library = ctypes.CDLL(library_name, use_errno=True)
        self._declare_functions()
        if self.library.sodium_init() < 0:
            fail("sodium_init failed")
        self.argon2id13 = int(self.library.crypto_pwhash_alg_argon2id13())

    def _declare_functions(self) -> None:
        void_pointer = ctypes.c_void_p
        unsigned_long_long = ctypes.c_ulonglong
        self.library.sodium_init.argtypes = []
        self.library.sodium_init.restype = ctypes.c_int
        self.library.crypto_pwhash_alg_argon2id13.argtypes = []
        self.library.crypto_pwhash_alg_argon2id13.restype = ctypes.c_int
        self.library.crypto_pwhash.argtypes = [
            void_pointer,
            unsigned_long_long,
            void_pointer,
            unsigned_long_long,
            void_pointer,
            unsigned_long_long,
            ctypes.c_size_t,
            ctypes.c_int,
        ]
        self.library.crypto_pwhash.restype = ctypes.c_int
        self.library.crypto_kdf_derive_from_key.argtypes = [
            void_pointer,
            ctypes.c_size_t,
            ctypes.c_uint64,
            void_pointer,
            void_pointer,
        ]
        self.library.crypto_kdf_derive_from_key.restype = ctypes.c_int
        self.library.crypto_aead_xchacha20poly1305_ietf_encrypt.argtypes = [
            void_pointer,
            ctypes.POINTER(unsigned_long_long),
            void_pointer,
            unsigned_long_long,
            void_pointer,
            unsigned_long_long,
            void_pointer,
            void_pointer,
            void_pointer,
        ]
        self.library.crypto_aead_xchacha20poly1305_ietf_encrypt.restype = ctypes.c_int
        self.library.crypto_aead_xchacha20poly1305_ietf_decrypt.argtypes = [
            void_pointer,
            ctypes.POINTER(unsigned_long_long),
            void_pointer,
            void_pointer,
            unsigned_long_long,
            void_pointer,
            unsigned_long_long,
            void_pointer,
            void_pointer,
        ]
        self.library.crypto_aead_xchacha20poly1305_ietf_decrypt.restype = ctypes.c_int

    def pwhash(self, password: bytes, salt: bytes, opslimit: int, memlimit: int) -> bytes:
        if len(salt) != 16:
            fail("Argon2id salt is not 16 bytes")
        output = (ctypes.c_ubyte * 32)()
        result = self.library.crypto_pwhash(
            output,
            32,
            ctypes_buffer(password),
            len(password),
            ctypes_buffer(salt),
            opslimit,
            memlimit,
            self.argon2id13,
        )
        if result != 0:
            fail("libsodium Argon2id derivation failed")
        return bytes(output)

    def kdf(self, key: bytes, context: bytes, subkey_id: int) -> bytes:
        if len(key) != 32 or len(context) != 8:
            fail("libsodium KDF key/context length is invalid")
        output = (ctypes.c_ubyte * 32)()
        result = self.library.crypto_kdf_derive_from_key(
            output,
            32,
            subkey_id,
            ctypes_buffer(context),
            ctypes_buffer(key),
        )
        if result != 0:
            fail("libsodium subkey derivation failed")
        return bytes(output)

    def encrypt(self, plaintext: bytes, aad: bytes, nonce: bytes, key: bytes) -> bytes:
        if len(nonce) != 24 or len(key) != 32:
            fail("XChaCha20-Poly1305 nonce/key length is invalid")
        output = (ctypes.c_ubyte * (len(plaintext) + AEAD_TAG_LENGTH))()
        output_length = ctypes.c_ulonglong()
        result = self.library.crypto_aead_xchacha20poly1305_ietf_encrypt(
            output,
            ctypes.byref(output_length),
            ctypes_buffer(plaintext),
            len(plaintext),
            ctypes_buffer(aad),
            len(aad),
            None,
            ctypes_buffer(nonce),
            ctypes_buffer(key),
        )
        if result != 0 or output_length.value != len(output):
            fail("libsodium XChaCha20-Poly1305 encryption failed")
        return bytes(output)

    def decrypt(
        self, ciphertext: bytes, aad: bytes, nonce: bytes, key: bytes
    ) -> bytes | None:
        if len(ciphertext) < AEAD_TAG_LENGTH or len(nonce) != 24 or len(key) != 32:
            return None
        output = (ctypes.c_ubyte * (len(ciphertext) - AEAD_TAG_LENGTH))()
        output_length = ctypes.c_ulonglong()
        result = self.library.crypto_aead_xchacha20poly1305_ietf_decrypt(
            output,
            ctypes.byref(output_length),
            None,
            ctypes_buffer(ciphertext),
            len(ciphertext),
            ctypes_buffer(aad),
            len(aad),
            ctypes_buffer(nonce),
            ctypes_buffer(key),
        )
        if result != 0:
            return None
        if output_length.value != len(output):
            fail("libsodium returned an unexpected AEAD plaintext length")
        return bytes(output)


def deterministic_padding(length: int) -> bytes:
    if length < 0:
        fail("negative padding length")
    return bytes(((index * 29 + 0x5A) & 0xFF) for index in range(length))


def recovery_base32_encode(material: bytes) -> str:
    accumulator = 0
    bits = 0
    encoded: list[str] = []
    for byte in material:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            encoded.append(CROCKFORD_ALPHABET[(accumulator >> bits) & 31])
            accumulator &= (1 << bits) - 1 if bits else 0
    if bits:
        encoded.append(CROCKFORD_ALPHABET[(accumulator << (5 - bits)) & 31])
    return "PV1R-" + "-".join(
        "".join(encoded[index : index + 5]) for index in range(0, len(encoded), 5)
    )


def recovery_base32_decode(encoded: str) -> bytes:
    stripped = encoded.strip()
    if stripped[:4].upper() != "PV1R":
        fail("recovery vector has the wrong prefix")
    aliases = {"O": "0", "I": "1", "L": "1"}
    normalized = "".join(
        character.upper()
        for character in stripped[4:]
        if character != "-" and not character.isspace()
    )
    accumulator = 0
    bits = 0
    decoded = bytearray()
    for character in normalized:
        character = aliases.get(character, character)
        try:
            value = CROCKFORD_ALPHABET.index(character)
        except ValueError as error:
            raise VectorError("recovery vector contains a non-Crockford character") from error
        accumulator = (accumulator << 5) | value
        bits += 5
        if bits >= 8:
            bits -= 8
            decoded.append((accumulator >> bits) & 0xFF)
            accumulator &= (1 << bits) - 1 if bits else 0
    if accumulator != 0:
        fail("recovery vector has a nonzero unused tail")
    return bytes(decoded)


def recovery_material() -> tuple[bytes, str]:
    checksum = hashlib.blake2b(
        SYNTHETIC_VAULT_ID + SYNTHETIC_RECOVERY_KEY, digest_size=32
    ).digest()[:5]
    return checksum, recovery_base32_encode(SYNTHETIC_RECOVERY_KEY + checksum)


def build_vector(sodium: Sodium) -> tuple[bytes, dict[str, Any]]:
    cbor = encode_payload()
    if CborReader(cbor).complete_item() != expected_payload():
        fail("the independent CBOR encoder and decoder disagree")

    header = bytearray(HEADER_LENGTH)
    header[0:8] = MAGIC
    struct.pack_into("<HHII", header, 8, FORMAT_MAJOR, FORMAT_MINOR, HEADER_LENGTH, 0)
    header[20:36] = SYNTHETIC_VAULT_ID
    struct.pack_into(
        "<HHHHQQ",
        header,
        36,
        KDF_ID_ARGON2ID13,
        AEAD_ID_XCHACHA20POLY1305,
        AEAD_ID_XCHACHA20POLY1305,
        SLOT_COUNT,
        PASSWORD_OPSLIMIT,
        PASSWORD_MEMLIMIT,
    )
    header[60:76] = SYNTHETIC_PASSWORD_SALT
    header[76:100] = SYNTHETIC_PASSWORD_NONCE

    password_wrap_key = sodium.pwhash(
        SYNTHETIC_PASSWORD,
        SYNTHETIC_PASSWORD_SALT,
        PASSWORD_OPSLIMIT,
        PASSWORD_MEMLIMIT,
    )
    password_wrapped_vmk = sodium.encrypt(
        SYNTHETIC_VMK,
        bytes(header[:76]),
        SYNTHETIC_PASSWORD_NONCE,
        password_wrap_key,
    )
    header[100:148] = password_wrapped_vmk

    header[148:172] = SYNTHETIC_RECOVERY_NONCE
    recovery_wrap_key = sodium.kdf(SYNTHETIC_RECOVERY_KEY, RECOVERY_CONTEXT, 0)
    recovery_wrapped_vmk = sodium.encrypt(
        SYNTHETIC_VMK,
        bytes(header[:44]),
        SYNTHETIC_RECOVERY_NONCE,
        recovery_wrap_key,
    )
    header[172:220] = recovery_wrapped_vmk

    raw_body_length = 4 + len(cbor)
    padded_body_length = (
        (raw_body_length + BODY_BLOCK_SIZE - 1) // BODY_BLOCK_SIZE
    ) * BODY_BLOCK_SIZE
    padding = deterministic_padding(padded_body_length - raw_body_length)
    body_plaintext = struct.pack("<I", len(cbor)) + cbor + padding
    header[220:244] = SYNTHETIC_BODY_NONCE
    struct.pack_into("<Q", header, 244, padded_body_length + AEAD_TAG_LENGTH)
    body_key = sodium.kdf(SYNTHETIC_VMK, BODY_CONTEXT, 1)
    body_ciphertext = sodium.encrypt(
        body_plaintext,
        bytes(header),
        SYNTHETIC_BODY_NONCE,
        body_key,
    )
    fixture = bytes(header) + body_ciphertext

    recovery_checksum, recovery_text = recovery_material()
    manifest: dict[str, Any] = {
        "schema": "pvault-independent-vector-manifest-v1",
        "synthetic_only": True,
        "warning": "Public test material. Never reuse any credential, key, salt, or nonce.",
        "implementation": {
            "file": "tests/compat/pvault_v1_vector.py",
            "sha256": sha256_hex(GENERATOR.read_bytes()),
        },
        "format_contract": {
            "file": "docs/FORMAT.md",
            "sha256": sha256_hex(FORMAT_CONTRACT.read_bytes()),
            "major": FORMAT_MAJOR,
            "minor": FORMAT_MINOR,
        },
        "fixture": {
            "file": FIXTURE.name,
            "size": len(fixture),
            "sha256": sha256_hex(fixture),
        },
        "inputs": {
            "master_password_utf8": SYNTHETIC_PASSWORD.decode("ascii"),
            "vault_id_hex": SYNTHETIC_VAULT_ID.hex(),
            "recovery_key_hex": SYNTHETIC_RECOVERY_KEY.hex(),
            "vmk_hex": SYNTHETIC_VMK.hex(),
            "password_salt_hex": SYNTHETIC_PASSWORD_SALT.hex(),
            "password_nonce_hex": SYNTHETIC_PASSWORD_NONCE.hex(),
            "recovery_nonce_hex": SYNTHETIC_RECOVERY_NONCE.hex(),
            "body_nonce_hex": SYNTHETIC_BODY_NONCE.hex(),
            "password_opslimit": PASSWORD_OPSLIMIT,
            "password_memlimit": PASSWORD_MEMLIMIT,
            "padding_rule": "byte[i] = (i * 29 + 0x5a) mod 256",
        },
        "expected": {
            "header_hex": bytes(header).hex(),
            "header_sha256": sha256_hex(bytes(header)),
            "password_aad_hex": bytes(header[:76]).hex(),
            "password_wrap_key_hex": password_wrap_key.hex(),
            "password_wrapped_vmk_hex": password_wrapped_vmk.hex(),
            "recovery_aad_hex": bytes(header[:44]).hex(),
            "recovery_wrap_key_hex": recovery_wrap_key.hex(),
            "recovery_wrapped_vmk_hex": recovery_wrapped_vmk.hex(),
            "body_key_hex": body_key.hex(),
            "cbor_length": len(cbor),
            "cbor_hex": cbor.hex(),
            "cbor_sha256": sha256_hex(cbor),
            "padding_length": len(padding),
            "padding_sha256": sha256_hex(padding),
            "body_plaintext_sha256": sha256_hex(body_plaintext),
            "body_ciphertext_length": len(body_ciphertext),
            "body_ciphertext_sha256": sha256_hex(body_ciphertext),
            "recovery_checksum_hex": recovery_checksum.hex(),
            "recovery_text": recovery_text,
        },
    }
    return fixture, manifest


def canonical_manifest(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def expect_equal(actual: Any, expected: Any, description: str) -> None:
    if actual != expected:
        fail(f"{description} differs from the v1.0 contract")


def expect_rejected(description: str, operation: Callable[[], Any]) -> None:
    try:
        operation()
    except VectorError:
        return
    fail(f"negative vector was accepted: {description}")


def validate_declared_size(raw: bytes) -> tuple[bytes, bytes]:
    if len(raw) < HEADER_LENGTH:
        fail("fixture is shorter than the fixed header")
    header = raw[:HEADER_LENGTH]
    declared_header_length = struct.unpack_from("<I", header, 12)[0]
    if declared_header_length != HEADER_LENGTH:
        fail("declared header length differs from format v1.0")
    declared_body_length = struct.unpack_from("<Q", header, 244)[0]
    actual_body_length = len(raw) - HEADER_LENGTH
    if declared_body_length != actual_body_length:
        fail("declared body length differs from the exact remaining file size")
    if declared_body_length < BODY_BLOCK_SIZE + AEAD_TAG_LENGTH:
        fail("body ciphertext is smaller than one padded block")
    if (declared_body_length - AEAD_TAG_LENGTH) % BODY_BLOCK_SIZE != 0:
        fail("body ciphertext is not block-aligned")
    return header, raw[HEADER_LENGTH:]


def verify_cbor_negative_samples() -> None:
    samples = {
        "non-minimal unsigned integer": bytes.fromhex("1817"),
        "non-minimal byte-string length": bytes.fromhex("580100"),
        "non-minimal map key": bytes.fromhex("a1180001"),
        "map keys outside canonical order": bytes.fromhex("a201010001"),
    }
    for description, sample in samples.items():
        expect_rejected(description, lambda sample=sample: CborReader(sample).complete_item())


def verify_fixture(raw: bytes, manifest: dict[str, Any], sodium: Sodium) -> None:
    header, body_ciphertext = validate_declared_size(raw)

    expect_rejected("one-byte truncation", lambda: validate_declared_size(raw[:-1]))
    expect_rejected("one trailing byte", lambda: validate_declared_size(raw + b"\x00"))
    verify_cbor_negative_samples()

    expect_equal(header[:8], MAGIC, "header magic")
    expect_equal(struct.unpack_from("<H", header, 8)[0], FORMAT_MAJOR, "format major")
    expect_equal(struct.unpack_from("<H", header, 10)[0], FORMAT_MINOR, "format minor")
    expect_equal(struct.unpack_from("<I", header, 12)[0], HEADER_LENGTH, "header length")
    expect_equal(struct.unpack_from("<I", header, 16)[0], 0, "header flags")
    expect_equal(header[20:36], SYNTHETIC_VAULT_ID, "vault ID")
    expect_equal(struct.unpack_from("<H", header, 36)[0], KDF_ID_ARGON2ID13, "KDF ID")
    expect_equal(
        struct.unpack_from("<H", header, 38)[0],
        AEAD_ID_XCHACHA20POLY1305,
        "wrap AEAD ID",
    )
    expect_equal(
        struct.unpack_from("<H", header, 40)[0],
        AEAD_ID_XCHACHA20POLY1305,
        "body AEAD ID",
    )
    expect_equal(struct.unpack_from("<H", header, 42)[0], SLOT_COUNT, "slot count")
    opslimit = struct.unpack_from("<Q", header, 44)[0]
    memlimit = struct.unpack_from("<Q", header, 52)[0]
    expect_equal(opslimit, PASSWORD_OPSLIMIT, "password opslimit")
    expect_equal(memlimit, PASSWORD_MEMLIMIT, "password memlimit")
    expect_equal(header[60:76], SYNTHETIC_PASSWORD_SALT, "password salt")
    expect_equal(header[76:100], SYNTHETIC_PASSWORD_NONCE, "password nonce")
    expect_equal(header[148:172], SYNTHETIC_RECOVERY_NONCE, "recovery nonce")
    expect_equal(header[220:244], SYNTHETIC_BODY_NONCE, "body nonce")
    declared_body_length = struct.unpack_from("<Q", header, 244)[0]
    expect_equal(declared_body_length, len(body_ciphertext), "body ciphertext length")
    expect_equal(len(raw), HEADER_LENGTH + declared_body_length, "fixture size")

    password_wrap_key = sodium.pwhash(
        SYNTHETIC_PASSWORD, header[60:76], opslimit, memlimit
    )
    password_vmk = sodium.decrypt(
        header[100:148], header[:76], header[76:100], password_wrap_key
    )
    expect_equal(password_vmk, SYNTHETIC_VMK, "password keyslot plaintext")
    recovery_wrap_key = sodium.kdf(SYNTHETIC_RECOVERY_KEY, RECOVERY_CONTEXT, 0)
    recovery_vmk = sodium.decrypt(
        header[172:220], header[:44], header[148:172], recovery_wrap_key
    )
    expect_equal(recovery_vmk, SYNTHETIC_VMK, "recovery keyslot plaintext")

    body_key = sodium.kdf(SYNTHETIC_VMK, BODY_CONTEXT, 1)
    body_plaintext = sodium.decrypt(
        body_ciphertext, header, header[220:244], body_key
    )
    if body_plaintext is None:
        fail("body authentication failed")
    if len(body_plaintext) % BODY_BLOCK_SIZE != 0:
        fail("decrypted body is not block-aligned")
    cbor_length = struct.unpack_from("<I", body_plaintext, 0)[0]
    if cbor_length == 0 or cbor_length > len(body_plaintext) - 4:
        fail("decrypted CBOR length is invalid")
    cbor = body_plaintext[4 : 4 + cbor_length]
    padding = body_plaintext[4 + cbor_length :]
    expect_equal(CborReader(cbor).complete_item(), expected_payload(), "CBOR payload")
    expect_equal(cbor, encode_payload(), "deterministic CBOR bytes")
    expect_equal(padding, deterministic_padding(len(padding)), "fixed test padding")

    checksum, recovery_text = recovery_material()
    decoded_recovery = recovery_base32_decode(recovery_text)
    expect_equal(
        decoded_recovery,
        SYNTHETIC_RECOVERY_KEY + checksum,
        "recovery text material",
    )

    tampered_password_slot = bytearray(header[100:148])
    tampered_password_slot[0] ^= 1
    if sodium.decrypt(
        bytes(tampered_password_slot), header[:76], header[76:100], password_wrap_key
    ) is not None:
        fail("tampered password keyslot authenticated")
    tampered_recovery_slot = bytearray(header[172:220])
    tampered_recovery_slot[-1] ^= 1
    if sodium.decrypt(
        bytes(tampered_recovery_slot), header[:44], header[148:172], recovery_wrap_key
    ) is not None:
        fail("tampered recovery keyslot authenticated")
    tampered_body = bytearray(body_ciphertext)
    tampered_body[-1] ^= 1
    if sodium.decrypt(bytes(tampered_body), header, header[220:244], body_key) is not None:
        fail("tampered body authenticated")
    for byte_index in range(HEADER_LENGTH):
        tampered_header = bytearray(header)
        tampered_header[byte_index] ^= 1
        tampered_header_bytes = bytes(tampered_header)
        if sodium.decrypt(
            body_ciphertext,
            tampered_header_bytes,
            tampered_header_bytes[220:244],
            body_key,
        ) is not None:
            fail(f"body authenticated after header bit flip at byte {byte_index}")

    expected_manifest_checks = {
        "header_sha256": sha256_hex(header),
        "cbor_sha256": sha256_hex(cbor),
        "padding_sha256": sha256_hex(padding),
        "body_plaintext_sha256": sha256_hex(body_plaintext),
        "body_ciphertext_sha256": sha256_hex(body_ciphertext),
        "recovery_checksum_hex": checksum.hex(),
        "recovery_text": recovery_text,
    }
    for name, value in expected_manifest_checks.items():
        expect_equal(manifest["expected"].get(name), value, f"manifest {name}")
    expect_equal(manifest["fixture"].get("sha256"), sha256_hex(raw), "fixture digest")
    expect_equal(manifest["fixture"].get("size"), len(raw), "manifest fixture size")


def generate(sodium: Sodium) -> None:
    fixture, manifest = build_vector(sodium)
    FIXTURE.write_bytes(fixture)
    MANIFEST.write_bytes(canonical_manifest(manifest))
    print(
        f"generated {FIXTURE.name} ({len(fixture)} bytes, sha256={sha256_hex(fixture)})"
    )


def check(sodium: Sodium) -> None:
    if not FIXTURE.is_file() or not MANIFEST.is_file():
        fail("committed vector or manifest is missing; run --generate")
    committed_fixture = FIXTURE.read_bytes()
    committed_manifest_bytes = MANIFEST.read_bytes()
    try:
        committed_manifest = json.loads(committed_manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VectorError("manifest is not canonical UTF-8 JSON") from error
    expected_fixture, expected_manifest = build_vector(sodium)
    expected_manifest_bytes = canonical_manifest(expected_manifest)
    if committed_fixture != expected_fixture:
        fail(
            "committed fixture is not reproducible: "
            f"actual sha256={sha256_hex(committed_fixture)}, "
            f"expected sha256={sha256_hex(expected_fixture)}"
        )
    if committed_manifest_bytes != expected_manifest_bytes:
        fail(
            "committed manifest is not canonical/reproducible: "
            f"actual sha256={sha256_hex(committed_manifest_bytes)}, "
            f"expected sha256={sha256_hex(expected_manifest_bytes)}"
        )
    expect_equal(committed_manifest, expected_manifest, "parsed manifest")
    verify_fixture(committed_fixture, committed_manifest, sodium)
    print(
        f"verified {FIXTURE.name} ({len(committed_fixture)} bytes, "
        f"sha256={sha256_hex(committed_fixture)})"
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--generate",
        action="store_true",
        help="regenerate the committed binary fixture and canonical manifest",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="verify committed bytes, cryptography, CBOR, recovery text, and manifest",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        sodium = Sodium()
        if arguments.generate:
            generate(sodium)
        else:
            check(sodium)
    except (OSError, VectorError) as error:
        print(f"pvault v1 vector: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
