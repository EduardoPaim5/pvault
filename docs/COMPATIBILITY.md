# Format compatibility and migration contract

This document defines how PVault applications handle file-format evolution. It
is a safety contract for future implementations, not a claim that migration is
already implemented. The current file format is the pre-alpha v1.0 draft
specified in [`FORMAT.md`](FORMAT.md).

## Version domains

Application versions and file-format versions are independent:

- the application version identifies a build, package, CLI behavior, and
  security-support line, for example `0.1.0-pre-alpha`;
- the file-format version identifies the authenticated bytes and payload schema
  stored in a vault, for example `1.0`.

Changing the application version does not imply a format change. Fixes that do
not alter the serialized contract must continue to read and write the same
format version. Conversely, a format change requires an explicit compatibility
decision even when the application remains in the same major version.

## Freeze of format v1.0

Format v1.0 is designed to be freezeable, but it is not frozen while its status
in `FORMAT.md` is `pre-alpha draft`. Freezing it requires all of the following:

1. the normative specification and every bound are complete;
2. byte-exact positive and negative vectors cover the header, both keyslots,
   body AAD, deterministic CBOR, recovery text, and rejection behavior;
3. vectors are reproduced by an implementation independent of the writer, or
   independently reviewed against the specification;
4. parser, cryptography, secure-memory, persistence, and recovery findings from
   the release audit are resolved;
5. backup, restore, and rescue drills succeed on a separate machine; and
6. a signed release identifies the frozen specification, vectors, and source
   revision.

After that release, incompatible byte or semantic changes must use a new format
version. They must not be introduced by silently reinterpreting v1.0 fields,
flags, algorithm identifiers, canonical encodings, or limits.

## Fail-closed reader contract

A reader must treat the format boundary as hostile and fail closed:

- unsupported major or minor versions, header sizes, flags, algorithms,
  keyslots, limits, and encodings are rejected;
- unauthenticated header values are bounded before expensive KDF work or body
  allocation;
- no payload byte is parsed, displayed, copied, or migrated before successful
  AEAD authentication;
- malformed, non-canonical, truncated, extended, or semantically invalid
  payloads are rejected as a whole; and
- a reader that cannot prove support must not rewrite, repair, truncate, or
  partially import the source vault.

The reader returns a dedicated unsupported-version classification, separate
from authentication and ordinary malformed-format errors, when the cleartext
preamble names a version for which no decoder exists. Because those version
bytes are not authenticated until body AEAD succeeds, that classification can
also be caused by corruption or tampering; it is not proof that the file is a
genuine newer vault and must never authorize migration, repair, or rewriting.
Renaming a file, editing its version bytes, or forcing a parser past that result
is never a supported recovery procedure.

## No migration during ordinary open

Normal operations such as `list`, `show`, `copy`, `doctor`, and authentication
must never migrate a vault as a side effect. Reading an older supported format
does not grant permission to rewrite it. There is no unattended or implicit
auto-migration.

A future migration must be an explicit command or an equally explicit UI
operation. Before it starts, PVault must report the source and destination
format versions, required free space, backup location, and whether rollback can
discard changes made after migration. The user must confirm the operation.

## Transactional migration

Migration from a supported source format to a newer format must use this
transaction boundary:

1. acquire the stable vault writer lock;
2. open and authenticate the complete source snapshot, validate its canonical
   representation and semantics, and record a cryptographic hash of its exact
   bytes;
3. create an exact encrypted pre-migration backup with mode `0600`, synchronize
   the file and its parent directory, and verify it by readback;
4. keep that backup in a migration-backup namespace that normal retention and
   pruning never inspect or delete;
5. transform data only in locked, clear-on-release memory, rejecting any field
   that cannot be represented without loss;
6. serialize the destination canonically with fresh nonces where required,
   authenticate it, and reopen it with the destination reader;
7. recheck the live source hash so a stale migrator cannot overwrite a newer
   writer;
8. write a temporary file in the vault directory, synchronize it, atomically
   rename it over the live path, synchronize the directory, and verify the
   installed bytes by readback; and
9. report post-rename synchronization or readback failures as uncertain
   durability, preserving every recovery artifact.

Any failure before the atomic rename must leave the source vault byte-for-byte
unchanged. A migration must never delete or overwrite its only authenticated
source. Migration backups are excluded from ordinary `backup_retention`; only
an explicit cleanup operation may remove them after a separate recovery drill.

## Compatibility lifetime

Once a format is frozen by a signed release, it does not expire merely because
the application advances. A current release must retain a read-only decoder for
every previously frozen format and an explicit, tested path from each of those
formats to the current writer. A user who skips application releases must not
need to locate and run every intermediate version to recover a vault.

At minimum, continuous integration must exercise the current writer `N`, the
immediately preceding writer `N-1`, and every frozen historical read fixture.
For each supported source format the application must:

- read and authenticate it without modifying it;
- provide a direct or bundled, explicitly selected migration to the current
  format;
- preserve a source-format pre-migration backup and rescue procedure; and
- prove semantic preservation with the versioned conformance fixture.

Format v1.0 has no predecessor, so cross-version migration starts with its
successor. A security release may deliberately remove an unsafe legacy decoder
from the main process, but it must document the reason, preserve the source
file, and ship a signed isolated rescue reader or migrator when safely possible.
The release is not allowed to make the only remaining authenticated copy
unreadable. Compatibility must never override fail-closed validation.

## Application rollback and format downgrade

Rolling back an application is not the same as downgrading a vault. An older
application encountering a newer format must reject it without writing. To roll
back safely, keep the newer vault untouched, copy the verified pre-migration
backup to a separate private path, and open that copy with the signed release
that supports its format.

PVault does not promise an in-place downgrade. Any future downgrade must be an
explicit export into a new encrypted vault, must reject lossy conversion by
default, and must preserve the newer source. Returning to a pre-migration
snapshot also discards all mutations made after migration; PVault cannot merge
those histories automatically.

Authenticated snapshots do not provide freshness. Restoring an older valid
snapshot is a deliberate rollback that the cryptography cannot distinguish
from the latest state. The operator must preserve the current snapshot before
restore and verify the intended generation and records afterward.

## Rescue obligations

Every release that first writes a new stable format must publish, alongside its
signed artifacts:

- the exact source and destination specifications and conformance vectors;
- the last signed reader for the previous format;
- instructions for authenticating a copy without modifying the source;
- the migration-backup naming and verification procedure; and
- a tested path to create a new encrypted vault when in-place migration cannot
  complete safely.

Rescue always operates on a private copy. It must not weaken version checks,
skip AEAD verification, expose plaintext by default, or make the only surviving
snapshot writable. Users must retain the recovery key, authenticated encrypted
snapshots, and the signed reader needed for each format on which they depend.
