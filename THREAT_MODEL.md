# PVault threat model

## Status and scope

This document describes the intended Linux desktop design for the PVault 0.1
format and CLI. It is a design contract, not a security certification. Android,
network synchronization, browser extensions, TOTP, attachments, and shared
vaults are outside this version's boundary.

PVault remains pre-alpha and has not received an independent security audit.
The properties below must not be interpreted as approval to store real
credentials or the only copy of important data.

## Assets

PVault treats the following as secrets or integrity-sensitive state:

- the master password;
- the recovery key;
- the vault master key (VMK) and all derived keys;
- record passwords, usernames, URLs, notes, tags, custom fields, timestamps, and
  record identifiers;
- the complete decrypted payload and generated passwords; and
- the ordering, revision, and deletion state of records.

The configuration is not secret, but it is integrity-sensitive because it
selects the vault path, retention behavior, clipboard lifetime, session
timeout, and whether the external rofi picker is used.

The encrypted file's existence, size rounded to its padding boundary, update
time, backup count, and local pathname are not hidden.

## Trust boundaries

PVault trusts:

- the local kernel, CPU, libc, libsodium, libcbor, ncurses, compiler, and loader;
- the PVault binaries installed by the user;
- the terminal used to enter the master password;
- the current user's account while the vault is unlocked; and
- the randomness supplied through libsodium.

`xclip`, `wl-copy`, optional `rofi`, the X11/Wayland compositor, terminal,
window manager, and clipboard manager are outside the cryptographic core. Once
a password is sent to the clipboard owner, those components can observe or
retain it. Opting into rofi exposes each sanitized display title and a random
token valid only for that picker invocation to the external process. The token
is not the persistent record identifier. Rofi receives only an allowlisted
display, runtime, authentication, home, and locale environment, but remains
outside the trusted core. The in-process picker is the default.

## Adversaries considered

The design aims to resist:

- an attacker who obtains the vault, an encrypted backup, or storage-server
  snapshot while it is closed;
- accidental or malicious modification, truncation, reordering, or extension of
  vault bytes;
- opportunistic recovery of plaintext from ordinary swap or core dumps;
- secrets accidentally exposed through command arguments, environment
  variables, shell history, normal stdout, logs, or plaintext temporary files;
- crashes or power loss during a vault update; and
- concurrent local writers that would otherwise silently overwrite one another.

## Explicitly out of scope

PVault cannot reliably protect secrets from:

- root, a compromised kernel, hypervisor, firmware, CPU, or malicious hardware;
- a keylogger, screen/TTY capture, debugger, injected library, or process with
  permission to inspect the unlocked process;
- a compromised build, dependency, package mirror, or malicious source change;
- another X11 client, a hostile compositor, or a clipboard manager that reads a
  password before expiration;
- a relying application after the password has been pasted;
- physical memory attacks, registers, library-internal temporary buffers, and
  every compiler-generated copy;
- denial of service, deletion of all vault copies, or storage exhaustion;
- a weak master password under an offline guessing attack; or
- coercion and shoulder surfing.

## Security properties

### Vault at rest

The master password is processed with Argon2id13 using parameters stored in the
password keyslot. The derived key authenticates and unwraps a random 256-bit
VMK. A separately generated recovery key authenticates and unwraps the same VMK
through a distinct keyslot. The VMK derives a payload key using domain-separated
libsodium KDF context. The body is encrypted and authenticated with
XChaCha20-Poly1305.

The serialized header is authenticated as associated data. All record content
and metadata are inside the encrypted payload. A wrong password, wrong recovery
key, corrupted keyslot, and modified ciphertext must fail closed before payload
records are exposed.

AEAD authenticates a snapshot but does not prove freshness. Restoring an older,
otherwise valid vault is not cryptographically detectable in 0.1. Local
generation counters support diagnostics and future synchronization; they are
not an anti-rollback oracle.

### Input validation

The fixed header is decoded field by field with explicit little-endian widths.
Algorithm identifiers, versions, flags, KDF limits, ciphertext sizes, CBOR
types, collection counts, and every arithmetic operation are validated before
large allocation or interpretation. The authenticated CBOR profile is
deterministic and does not accept indefinite-length items, duplicate keys, or
non-minimal encodings.

This validation also limits denial-of-service from an unauthenticated header:
the file cannot select arbitrary Argon2 memory/operation costs or force an
unbounded allocation.

The optional configuration is opened relative to a validated owner-controlled
directory descriptor. Symlinks, hardlinks, non-regular objects, unsafe owner or
mode metadata, duplicate keys, embedded NUL bytes, and oversized input fail
closed. Parsing occurs into a temporary configuration and is committed only
after the complete file is valid.

### CLI metadata boundary

Record selectors are treated as protected metadata. `edit`, `remove`, `show`,
and `copy` are queryless and select through the in-process picker attached to
`/dev/tty`. Earlier pre-alpha positional selectors are rejected rather than
silently reinterpreted. Supported invocations therefore do not require a title,
username, URL, tag, or persistent record ID in process arguments or ordinary
shell history. Rejection cannot retract an argument that the user already gave
to the shell and kernel, so legacy forms must be tested only with synthetic
text. When copying a custom field, `--field custom` lists sanitized names on
`/dev/tty` and selects one by ordinal; duplicate names remain addressable and
arbitrary custom names are not accepted in supported `argv`. Successful `add`
and `edit` status messages do not contain
record identifiers.

Decrypted metadata from `list`, `show`, and a non-copying `pick` is emitted to
stdout only when stdout is a terminal. Authenticated identity from
`rescue verify` follows the same rule. `--allow-redirect` is an explicit opt-in
that permits those bytes to reach a caller-chosen non-terminal destination; it
does not make that destination private, encrypted, short-lived, or safe from
logs. The interactive `shell` requires both stdin and stdout to be terminals.
The terminal itself remains trusted as stated above, and terminal recording is
outside this boundary.

### Memory lifecycle

Master passwords, recovery material, VMK, derived keys, generated passwords,
and plaintext arenas are allocated through libsodium's secure-memory APIs and
must be successfully page-locked. Sensitive buffers are cleared before release.
Core dumps are disabled and sensitive mappings are excluded from dumps where the
platform permits it.

`mlock` reduces ordinary swap exposure; it does not stop privileged reads,
hibernation images, DMA, registers, library copies, or a compromised process.
Failure to lock required secret memory is fatal rather than a silent downgrade.

The master password is cleared after derivation, the wrapping key after VMK
unwrap, and the payload arena and VMK on lock, timeout, and normal exit. During
hidden TTY input, catchable interrupt, termination, hangup, quit, and stop
signals first restore the terminal settings and are then re-raised. On process
termination the kernel tears down the remaining locked mappings; `SIGKILL`,
power loss, and kernel failure cannot run application cleanup code.

### Filesystem updates and recovery

The data and backup directories are private to the user; files are created mode
`0600` under a `077` umask. Writers serialize through a stable lockfile opened
relative to a held immediate-parent directory descriptor. The lock, active
entry, temporary file, automatic backup directory, commit, and readback remain
confined to that descriptor. An update is written to a new file in the same
directory, synchronized, renamed atomically, and followed by a directory
synchronization. `init` and backup publication use no-replace renames. The
current vault is never opened with `O_TRUNC`.

Snapshot reads validate the opened descriptor rather than trusting path metadata:
the immediate parent must be current-user-owned and not group/world-writable,
and the file must be regular, current-user-owned, single-linked, and exactly
0400 or 0600. `O_NOFOLLOW` applies to the immediate-parent entry and the final
snapshot entry; intermediate pathname components are not claimed to be
symlink-free. Nonblocking descriptor opens avoid blocking on a substituted
special file. The parent pathname is revalidated around publication so movement
is reported, while the held descriptor prevents redirecting the commit to a
replacement directory. These checks do not defend against root, an untrusted
ancestor that can hide or move directories, or another process already
controlling the same Unix account.

Previous encrypted snapshots are retained according to the configured backup
limit. Automatic retention is isolated by vault ID and numeric generation,
never targets manual, legacy, pre-restore, or pre-migration names, and occurs
only after the new active snapshot is committed and verified. Each managed
candidate must pass descriptor metadata checks, AEAD authentication, CBOR
validation, and an internal-generation/name match. Mode-0400 automatic entries
are pinned outside retention. A suspicious entry aborts pruning; retaining
excess ciphertext is the conservative failure mode. Backup publication is
temporary-file-first and atomic no-replace, so a killed writer does not publish
a partial deterministic name. Restore authenticates a candidate before
replacement, refuses to overwrite an unrelated non-PVault file or a different
vault lineage, and first preserves the well-framed current snapshot. These rules
reduce, but cannot eliminate,
filesystem, hardware, rollback, and operator failure.

The recovery file is not a backup of the vault. It is an alternate secret that
unlocks a surviving encrypted snapshot. Users must keep both encrypted backups
and the recovery key, preferably in separate offline locations.

### Rescue and application rollback

Rescue is not a permissive parser or repair mode. Structural inspection labels
the declared header values unauthenticated and never parses the body. Verification
requires a password or recovery key, successful keyslot unlock, complete body
AEAD authentication, canonical CBOR, and semantic validation before reporting
authenticated metadata. It never emits plaintext records, and refuses to send
authenticated identity to redirected stdout unless `--allow-redirect` was
given explicitly.

Authenticated recovery and application rollback publish a byte-exact encrypted
copy to a new, non-existing path. The temporary file is private, synchronized,
changed to mode 0400 before an atomic no-replace rename, synchronized through
the parent directory, and verified by readback. The source and configured active
vault are never written, renamed, chmodded, pruned, or removed. A hash proves
byte equality only; the recovery API accepts a hash obtained from a prior
authenticated open and structural inspection does not expose that value.

PVault never edits magic/version bytes, skips AEAD, imports a partial payload,
or exports plaintext as a rescue technique. Unsupported or corrupted versions
remain fail-closed. Cross-version migration will not exist until a real
successor format has an explicit decoder, writer, conformance fixture, recovery
credential policy, and lossless transactional route.

### Clipboard

PVault sends a requested field through an anonymous pipe to a short-lived
clipboard owner. The owner is started without a shell and the secret is never
an argument or environment variable. A supervisor expires only the owner it
created. The owner requests a parent-death signal from the kernel, so abrupt
supervisor death also terminates it. The inherited signal mask and the
SIGTERM/SIGINT/SIGHUP/SIGCHLD dispositions are normalized before the worker and
owner run. A successful transport result means the payload was written to the
pipe, its write end was closed, the owner was observed alive, and a
`CLOCK_BOOTTIME` timer was armed; suspend time therefore counts toward the TTL.
It cannot prove that an external backend consumed the pipe or acquired a usable
selection, so the CLI describes the value as queued rather than copied. PVault
does not overwrite the clipboard with an empty string, because that could erase
newer user content.

Textual UTF-8 values without NUL are offered to Wayland as
`text/plain;charset=utf-8`; other byte strings use `application/octet-stream`
so the transport does not falsely label arbitrary vault values as UTF-8. The
receiving application still decides whether it can consume that MIME type.

Expiration limits how long PVault offers the selection. It cannot revoke a copy
already requested by an application or clipboard manager. X11 provides no
isolation between mutually untrusted clients in the same session. Clipboard use
therefore remains an acknowledged exposure.

## Operational assumptions

Users are expected to:

- use a strong, unique, randomly generated master passphrase; the creation-time
  weak-pattern filter is only a guardrail and not an entropy estimate;
- verify release signatures/checksums when releases become available;
- keep the operating system and dependencies updated;
- use encrypted swap or disable swap and avoid unencrypted hibernation;
- keep the recovery key separate from encrypted backups;
- test recovery with synthetic data before relying on it;
- use `--allow-redirect` only for an intentional destination whose permissions,
  lifetime, logs, and downstream consumers they have evaluated;
- avoid persistent clipboard managers or configure them to ignore sensitive
  selections; and
- lock the vault before leaving the session.

## Future changes

Android and synchronization require a revised threat model covering device
identity, Keystore/biometrics, rollback/fork attacks, revocation, conflict
preservation, network metadata, and server compromise. They must not be treated
as implied properties of the 0.1 desktop design.
