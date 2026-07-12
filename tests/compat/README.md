# Independent PVault v1.0 compatibility vector

This directory contains one complete, deterministic PVault v1.0 snapshot and
the public inputs needed to reproduce every byte. All credentials, keys, IDs,
salts, nonces, record values, and padding bytes are synthetic test material.
They are intentionally public and **must never be reused in a real vault**.

The vector generator is an implementation independent of the PVault C code. It
does not import, execute, or bind to PVault. It implements the fixed header,
deterministic CBOR subset, body framing, Crockford recovery text, and validation
directly from `docs/FORMAT.md`. Python's standard library handles framing,
CBOR, JSON, BLAKE2b, and SHA-256; `ctypes` calls the system libsodium only for
Argon2id, `crypto_kdf`, and XChaCha20-Poly1305.

Files:

- `pvault-v1-synthetic.bin`: complete versioned snapshot. The `.bin` suffix is
  deliberate: publication controls reject real `.pvlt` files.
- `pvault-v1-synthetic.json`: canonical manifest with public inputs, expected
  intermediate values, hashes, recovery text, and format-contract/generator
  digests.
- `pvault_v1_vector.py`: deterministic generator and independent verifier.

Verify the committed vector without writing files:

```sh
python3 tests/compat/pvault_v1_vector.py --check
```

`--check` is also the default and is registered as the
`pvault_v1_compat_vector` CTest. It regenerates the expected bytes in memory,
compares the committed artifacts byte for byte, then independently parses and
authenticates both keyslots and the complete body. It also validates canonical
CBOR, fixed padding, recovery checksum/text, and manifest hashes. Its negative
checks flip one bit in every one of the 252 authenticated header bytes, always
using the resulting header and body nonce for the attempted decryption. It also
rejects one-byte truncation, trailing file data, non-minimal CBOR integers and
lengths, non-minimal map keys, and map keys outside canonical order.

Regenerate after an intentional format-vector change:

```sh
python3 tests/compat/pvault_v1_vector.py --generate
python3 tests/compat/pvault_v1_vector.py --check
```

The fixed salts, nonces, VMK, recovery key, and padding model controlled outputs
from a randomness source solely to make the fixture reproducible. A production
writer must continue to obtain fresh random values through `randombytes_buf()`;
deterministic values would be catastrophic outside this public test vector.
