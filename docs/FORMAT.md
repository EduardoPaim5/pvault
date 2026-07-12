# PVault file format version 1.0

- Status: **pre-alpha draft**
- Magic: `PVLT 0d 0a 1a 0a`
- Default extension: `.pvlt`

This document is the normative description of the PVault 1.0 desktop file
format. The format is not stable before PVault 1.0: pre-alpha builds may reject
or require migration of files produced by an earlier commit. A published test
vector manifest must bind itself to digests of this normative document and its
independent generator/verifier. A signed release binds those artifacts to the
complete source revision.

The words MUST, MUST NOT, SHOULD, and MAY are used as normative requirements.

## 1. Goals and non-goals

A PVault file is one authenticated encrypted snapshot. It hides all record
content and metadata, including record IDs, timestamps, titles, URLs, tags, and
deletion state. The cleartext header reveals the format version, algorithms,
KDF cost, vault identifier, keyslot count, nonces, and ciphertext length.

The format detects accidental or malicious modification but does not provide a
freshness oracle. An old, authentic snapshot can be replayed. Synchronization,
device authorization, signatures, and anti-rollback witnesses are not part of
version 1.0.

## 2. Primitive profile

All cryptographic operations use libsodium:

| ID | Meaning |
| --- | --- |
| KDF `1` | `crypto_pwhash_ALG_ARGON2ID13` |
| AEAD `1` | `crypto_aead_xchacha20poly1305_ietf` combined mode |

Sizes are fixed by this profile:

| Value | Bytes |
| --- | ---: |
| Salt | 16 |
| AEAD key | 32 |
| AEAD nonce | 24 |
| AEAD tag | 16 |
| Vault master key (VMK) | 32 |
| Wrapped VMK | 48 |
| Vault, record, and device IDs | 16 |

Every salt and nonce MUST be generated with `randombytes_buf()`. A writer MUST
never repeat a nonce with the same key. A password change creates a new salt and
password-slot nonce; recovery rotation creates a new recovery-slot nonce; every
body encryption creates a new body nonce.

## 3. File framing

```text
+--------------------------+ offset 0
| fixed header (252 bytes) |
+--------------------------+ offset 252
| body ciphertext          | body_ciphertext_len bytes
| (Poly1305 tag appended)  |
+--------------------------+ end of file
```

The file length MUST equal `252 + body_ciphertext_len`; trailing data is an
error. `body_ciphertext_len` includes the 16-byte AEAD tag. The decrypted body,
including its CBOR-length prefix and padding, MUST be no larger than 2 MiB.
Consequently a v1 ciphertext cannot exceed `2 MiB + 16` bytes.

Integers in the fixed header and decrypted-body prefix use unsigned
little-endian encoding. Signed timestamps exist only inside CBOR and use CBOR's
normal integer representation. No C structure is ever written directly.

### 3.1 Fixed header

| Offset | Size | Field | v1 requirement |
| ---: | ---: | --- | --- |
| 0 | 8 | `magic` | `50 56 4c 54 0d 0a 1a 0a` |
| 8 | 2 | `major` | `1` |
| 10 | 2 | `minor` | `0` |
| 12 | 4 | `header_len` | `252` |
| 16 | 4 | `flags` | `0` |
| 20 | 16 | `vault_id` | random, not all zero |
| 36 | 2 | `kdf_id` | `1` |
| 38 | 2 | `wrap_aead_id` | `1` |
| 40 | 2 | `body_aead_id` | `1` |
| 42 | 2 | `slot_count` | `2` |
| 44 | 8 | `password_opslimit` | bounded Argon2 operation cost |
| 52 | 8 | `password_memlimit` | bounded Argon2 memory cost in bytes |
| 60 | 16 | `password_salt` | random |
| 76 | 24 | `password_nonce` | random |
| 100 | 48 | `password_wrapped_vmk` | ciphertext then tag |
| 148 | 24 | `recovery_nonce` | random |
| 172 | 48 | `recovery_wrapped_vmk` | ciphertext then tag |
| 220 | 24 | `body_nonce` | random |
| 244 | 8 | `body_ciphertext_len` | includes tag |

Version 0.1 readers accept exactly major 1, minor 0, header length 252, two
keyslots, and zero flags. They reject unsupported versions, unknown flag bits,
algorithm IDs, or slot counts. A future format must allocate an explicit flag or
new version before changing this table.

Before calling Argon2 or allocating a body buffer, a reader MUST validate all
cleartext bounds. In particular it MUST reject Argon2 costs outside the
implementation's supported floor and ceiling and body lengths outside the v1
limit. Values in an unauthenticated header must never be allowed to request
unbounded work or memory.

## 4. Key hierarchy and keyslots

At vault creation, the writer generates a random 32-byte VMK. The VMK is not
derived from the master password; this permits password and recovery rotation
without changing the long-term vault identity.

### 4.1 Password keyslot

The password wrapping key (KEK) is the 32-byte output of:

```text
crypto_pwhash(
    outlen       = 32,
    password     = the exact bytes read from the TTY,
    salt         = password_salt,
    opslimit     = password_opslimit,
    memlimit     = password_memlimit,
    alg          = crypto_pwhash_ALG_ARGON2ID13
)
```

A v1.0 writer records exactly `opslimit = 3` and `memlimit = 268435456`
(256 MiB). A build may refuse creation when those resources cannot be securely
allocated; it MUST NOT silently substitute the library's current recommended
profile. A v1.0 reader accepts recorded operation costs from 3 through 10 and
memory costs from 268435456 through 1073741824 bytes, validating those numeric
bounds before invoking `crypto_pwhash`. These bounds are part of the format
contract, not aliases to mutable libsodium recommendation constants.

The KEK encrypts the 32-byte VMK in combined XChaCha20-Poly1305 mode using
`password_nonce`. The 48-byte result is stored in `password_wrapped_vmk`.

### 4.2 Recovery keyslot

The external recovery key is an independently generated 32-byte value. It is
not processed by Argon2id. A domain-separated 32-byte recovery wrapping key is
derived from it as follows:

```text
crypto_kdf_derive_from_key(
    subkey_len = 32,
    subkey_id  = 0,
    context    = "PVRECV01",
    master_key = recovery_key
)
```

The context is exactly eight ASCII bytes with no NUL terminator. The derived key
encrypts the same VMK using `recovery_nonce`, producing the 48-byte
`recovery_wrapped_vmk` value.

Possession of either the master password or the recovery key is therefore
sufficient to obtain the VMK. The recovery key MUST NOT be stored in cleartext
inside the vault or its normal configuration.

### 4.3 Keyslot associated data

The password slot's associated data is exactly header bytes 0 through 75
(76 bytes): the common preamble followed by the password operation cost, memory
cost, and salt. The recovery slot's associated data is exactly header bytes 0
through 43 (44 bytes), ending at `slot_count`.

```text
password_slot_aad = encoded_header[0:76]
recovery_slot_aad = encoded_header[0:44]
```

A writer constructs those header prefixes canonically before wrapping either
keyslot. A reader MUST reconstruct the serialized bytes rather than using an
in-memory C structure. The cleartext nonce is not part of its own AAD because it
is already an AEAD input; the wrapped value cannot be part of its own AAD. Body
encryption later authenticates the complete finalized header, including both
keyslot nonces and ciphertexts.

### 4.4 Body key

The VMK is a libsodium `crypto_kdf` master key. The body key is derived as:

```text
crypto_kdf_derive_from_key(
    subkey_len = 32,
    subkey_id  = 1,
    context    = "PVBODY01",
    master_key = VMK
)
```

The context is exactly eight ASCII bytes with no NUL terminator. Other future
subkeys MUST use a different context and/or subkey identifier.

## 5. Body encryption and padding

The complete serialized 252-byte header is the associated data for body AEAD.
The body key and `body_nonce` encrypt this plaintext:

```text
+-------------------------+
| cbor_len (le32)         |
+-------------------------+
| cbor_len bytes of CBOR  |
+-------------------------+
| random padding          |
+-------------------------+
```

The writer adds the minimum number of random padding bytes needed to make the
total plaintext length a multiple of 4096 bytes. If the prefix plus CBOR is
already aligned, zero padding bytes are added. The final plaintext length MUST
not exceed 2 MiB. Padding bytes are generated with `randombytes_buf()` and have
no internal format.

After successful AEAD authentication, the reader verifies:

- plaintext length is nonzero, at most 2 MiB, and a multiple of 4096;
- at least four bytes exist for `cbor_len`;
- `cbor_len` does not extend into or beyond the available body; and
- exactly `cbor_len` bytes form one accepted deterministic-CBOR item.

Padding is ignored only after these checks. A reader MUST NOT parse or expose
any body byte when AEAD authentication fails.

Whenever any authenticated header field changes, including a keyslot during
password or recovery rotation, the writer creates a new body nonce and
reencrypts the body so the header remains bound to the snapshot.

## 6. Deterministic CBOR profile

The payload follows RFC 8949 deterministic encoding with the additional
restrictions below:

- all maps and arrays have definite lengths;
- integers use their shortest representation;
- map keys are unsigned integers in ascending encoded order;
- maps have no duplicate or unknown keys;
- text strings contain valid UTF-8;
- floats, simple values other than `false` and `true`, tags, byte/text streams,
  and indefinite-length items are forbidden; and
- the decoder consumes exactly `cbor_len` bytes.

Decoders MUST enforce the byte and collection limits in section 7 while parsing,
not after building an unbounded object tree.

### 6.1 Top-level map

The top-level value is a map with exactly six entries:

| Key | Type | Meaning |
| ---: | --- | --- |
| 0 | unsigned | schema version; exactly `1` |
| 1 | unsigned | snapshot generation, 64-bit |
| 2 | byte string (16) | writer device ID |
| 3 | unsigned | non-negative vault creation time, Unix milliseconds |
| 4 | unsigned | non-negative vault update time, Unix milliseconds |
| 5 | array | records |

The vault ID is not repeated in CBOR; it is provided by the authenticated fixed
header. The generation increases for each successfully committed mutation. It
is diagnostic state, not rollback protection.

### 6.2 Record map

Every record is a map with exactly twelve entries:

| Key | Type | Meaning |
| ---: | --- | --- |
| 0 | byte string (16) | random record ID |
| 1 | unsigned | record revision, 64-bit |
| 2 | unsigned | non-negative creation time, Unix milliseconds |
| 3 | unsigned | non-negative update time, Unix milliseconds |
| 4 | unsigned | record flags |
| 5 | text | title |
| 6 | text | username |
| 7 | byte string | password; embedded NUL bytes are permitted |
| 8 | array of text | URLs |
| 9 | text | notes |
| 10 | array of text | tags |
| 11 | array of maps | custom fields |

Known record flags are:

| Bit | Value | Meaning |
| ---: | ---: | --- |
| 0 | `0x01` | deleted/tombstone |
| 1 | `0x02` | favorite |

Unknown bits are rejected. Record IDs within one payload MUST be unique and not
all zero.

### 6.3 Custom-field map

Each custom field is a map with exactly three entries:

| Key | Type | Meaning |
| ---: | --- | --- |
| 0 | text | field name |
| 1 | byte string | field value; embedded NUL bytes are permitted |
| 2 | unsigned | field flags |

The only known custom-field flag is bit 0 (`0x01`), meaning that the value is
secret and must not be shown by ordinary display commands. Unknown bits are
rejected.

## 7. Resource limits

Lengths below are encoded-byte limits, not Unicode character counts:

| Item | Maximum |
| --- | ---: |
| Total decrypted body | 2 MiB |
| Title | 1,024 bytes |
| Username | 4,096 bytes |
| Password | 65,536 bytes |
| One URL | 8,192 bytes |
| Notes | 262,144 bytes |
| One tag | 256 bytes |
| Custom-field name | 256 bytes |
| Custom-field value | 65,536 bytes |
| URLs per record | 64 |
| Tags per record | 64 |
| Custom fields per record | 64 |

The format does not set a separate record-count constant; record count is
bounded by the authenticated 2 MiB body, minimum CBOR encodings, available
locked memory, and checked arithmetic. Implementations MAY apply a lower local
operational limit but MUST report a limit error rather than partially loading a
snapshot.

Title and custom-field name are non-empty. Other strings and byte strings may be
empty. The CLI may impose stricter input policy without changing the decoder.

## 8. Recovery text encoding

The external recovery text represents `recovery_key || checksum`, where:

```text
recovery_key = 32 random bytes
checksum     = first 5 bytes of unkeyed BLAKE2b-256(
                   vault_id || recovery_key
               )
```

The 37 bytes are encoded most-significant bit first with the Crockford Base32
alphabet:

```text
0123456789ABCDEFGHJKMNPQRSTVWXYZ
```

No `I`, `L`, `O`, or `U` appears. The final four unused low bits of the 60th
character are zero. The canonical presentation is:

```text
PV1R-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-
     AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA
```

The line break and indentation above are illustrative only: the stored form is
one line ending in `\n`, with twelve groups of five Base32 characters. A decoder
accepts ASCII lowercase and ignores ASCII hyphens and whitespace. Following the
Crockford reading convention, `O` is accepted as `0`, and `I` or `L` is accepted
as `1`; writers never emit those aliases. A decoder MUST reject all other
characters, a missing `PV1R` prefix, a nonzero unused tail, the wrong decoded
length, or a checksum mismatch.

The checksum catches transcription mistakes and binds the code to one vault; it
is not an authentication substitute. The recovery-key AEAD tag remains the
cryptographic validity check.

## 9. Canonical validation order

A reader follows this order to prevent unauthenticated work and plaintext use:

1. Open and hold a validated immediate-parent directory descriptor, then open
   the final snapshot entry relative to it with `O_NOFOLLOW`; require a
   current-user regular file with one hard link and mode 0400 or 0600. No claim
   is made that intermediate pathname components are symlink-free.
2. Validate file size and read exactly 252 header bytes.
3. Decode fixed fields and validate magic, versions, flags, IDs, algorithm IDs,
   keyslot count, KDF bounds, and body length.
4. Verify the file has exactly the declared length.
5. Derive or obtain the selected keyslot key and authenticate/unlock the VMK.
6. Derive the body key and authenticate/decrypt the complete body with the
   serialized header as AAD.
7. Validate the body prefix, alignment, length, deterministic CBOR, semantic
   limits, flags, and unique IDs.
8. Expose read-only views only after every preceding step succeeds.

An authentication failure deliberately does not distinguish a wrong password,
wrong recovery key, corrupted keyslot, or modified body to the ordinary CLI.

## 10. Atomic snapshots and backups

Atomic replacement and backup retention are storage rules, not additional wire
fields. A conforming local writer:

1. opens the stable lockfile relative to a validated immediate-parent directory
   descriptor and holds both through commit and readback;
2. creates a mode-0600 temporary file relative to that same descriptor;
3. writes and `fsync()`s the complete new snapshot;
4. preserves the previous encrypted snapshot as a backup;
5. atomically renames the new snapshot over the active path; and
6. `fsync()`s the containing directory.

Initial creation MUST publish with no-replace semantics, so an entry created
after the absence check is never overwritten. Backup publication likewise MUST
write and synchronize a private temporary file and then atomically publish the
final name without replacement. The implementation reopens and compares the
configured parent pathname before and after publication; the held descriptor,
not this inherently racy comparison, confines all transaction mutations.

A backup is an exact PVault snapshot and uses this same format. Restore MUST
fully authenticate and parse a candidate before it can replace the current
file, MUST require the active snapshot's declared cleartext vault ID to equal
the authenticated candidate ID, and MUST preserve the pre-restore state first.
This lineage guard does not authenticate the active snapshot. Cross-vault
import is not an implicit restore operation.

PVault-created snapshots use mode 0600. Readers may also accept 0400 for an
explicitly read-only copy; group/world access, executable or special mode bits,
foreign ownership, multiple hard links, non-regular objects, symlinks, and an
unsafe immediate parent are storage-policy errors before parsing or KDF work.
An active 0400 snapshot MUST NOT be saved in place. It remains valid input for
open, backup, and restore. A mode-0400 automatic entry is pinned and excluded
from retention.

Automatic backup names are exactly
`auto-v1-<vault-id>-g<generation>.pvlt`, where `vault-id` is 32 lowercase
hexadecimal characters and `generation` is 20 decimal digits greater than zero.
The name records the generation of the previous snapshot, not the replacement.
Retention is numeric and scoped to the authenticated vault ID. It runs only
after atomic replacement and successful readback, and considers only exact,
private mode-0600 automatic entries at or below that previous generation. Each
candidate MUST pass AEAD body authentication, deterministic CBOR validation,
and equality between the authenticated internal generation and the filename
generation before any deletion phase begins. Pinned 0400, manual, legacy,
pre-restore, pre-migration, other-vault, future-generation, and near-match names
are never pruned. Suspicious metadata, framing, authentication, or generation
aborts the whole pruning pass before deletion. Deletions are revalidated and
any pass that removed an entry attempts a backup-directory `fsync()`, including
after a later deletion failure; pruning failure never rolls back or invalidates
an already verified update.

## 11. Compatibility and test vectors

A change to any of the following requires a new format minor/major version and
updated test vectors: offsets, widths, endian order, AAD bytes, KDF context or
subkey ID, CBOR keys/types, padding rule, recovery alphabet/bit packing, or
validation semantics.

The repository's binary vectors should cover at least:

- header encode/decode at every offset;
- password and recovery unlocking;
- deterministic CBOR byte-for-byte output;
- body encryption with fixed test-only inputs;
- recovery text and checksum;
- one-bit changes to every authenticated header region;
- truncation and trailing bytes;
- non-minimal and out-of-order CBOR; and
- each published size/count boundary.

Test vectors contain synthetic secrets only and are not evidence of production
security.

The current draft's representative deterministic fixture, canonical manifest,
and independent Python implementation are committed as
`tests/compat/pvault-v1-synthetic.bin`,
`tests/compat/pvault-v1-synthetic.json`, and
`tests/compat/pvault_v1_vector.py`. The manifest records SHA-256 digests of this
normative document and independent implementation. `tests/test_compat.c`
separately proves that the PVault C reader consumes the same fixed bytes,
reconstructs the expected semantic record, and writes the same canonical CBOR
and recovery text. This representative fixture does not by itself satisfy every
format-freeze criterion in `COMPATIBILITY.md`.
