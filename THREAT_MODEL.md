# PVault threat model

## Status and scope

This document describes the intended Linux desktop design for the PVault 0.1
format and CLI. It is a design contract, not a security certification. Android,
network synchronization, browser extensions, TOTP, attachments, and shared
vaults are outside this version's boundary.

## Assets

PVault treats the following as secrets or integrity-sensitive state:

- the master password;
- the recovery key;
- the vault master key (VMK) and all derived keys;
- record passwords, usernames, URLs, notes, tags, custom fields, timestamps, and
  record identifiers;
- the complete decrypted payload and generated passwords; and
- the ordering, revision, and deletion state of records.

The encrypted file's existence, size rounded to its padding boundary, update
time, backup count, and local pathname are not hidden.

## Trust boundaries

PVault trusts:

- the local kernel, CPU, libc, libsodium, libcbor, ncurses, compiler, and loader;
- the PVault binaries installed by the user;
- the terminal used to enter the master password;
- the current user's account while the vault is unlocked; and
- the randomness supplied through libsodium.

`xclip`, `wl-copy`, the X11/Wayland compositor, terminal, window manager, and
clipboard manager are outside the cryptographic core. Once a password is sent
to the clipboard owner, those components can observe or retain it.

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
`0600` under a `077` umask. Writers serialize through a stable lockfile. An
update is written to a new file in the same directory, synchronized, renamed
atomically, and followed by a directory synchronization. The current vault is
never opened with `O_TRUNC`.

Previous encrypted snapshots are retained according to the configured backup
limit. Restore authenticates a candidate before replacement and first preserves
the current state. These rules reduce, but cannot eliminate, filesystem,
hardware, and operator failure.

The recovery file is not a backup of the vault. It is an alternate secret that
unlocks a surviving encrypted snapshot. Users must keep both encrypted backups
and the recovery key, preferably in separate offline locations.

### Clipboard

PVault sends a requested field through an anonymous pipe to a short-lived
clipboard owner. The owner is started without a shell and the secret is never
an argument or environment variable. A supervisor expires only the owner it
created. The owner requests a parent-death signal from the kernel, so abrupt
supervisor death also terminates it. PVault does not overwrite the clipboard
with an empty string, because that could erase newer user content.

Expiration limits how long PVault offers the selection. It cannot revoke a copy
already requested by an application or clipboard manager. X11 provides no
isolation between mutually untrusted clients in the same session. Clipboard use
therefore remains an acknowledged exposure.

## Operational assumptions

Users are expected to:

- use a strong, unique master password;
- verify release signatures/checksums when releases become available;
- keep the operating system and dependencies updated;
- use encrypted swap or disable swap and avoid unencrypted hibernation;
- keep the recovery key separate from encrypted backups;
- test recovery with synthetic data before relying on it;
- avoid persistent clipboard managers or configure them to ignore sensitive
  selections; and
- lock the vault before leaving the session.

## Future changes

Android and synchronization require a revised threat model covering device
identity, Keystore/biometrics, rollback/fork attacks, revocation, conflict
preservation, network metadata, and server compromise. They must not be treated
as implied properties of the 0.1 desktop design.
