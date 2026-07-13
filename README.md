# PVault

PVault is an experimental, local-first password vault for Linux, written in
C11. It is designed for a keyboard-driven workflow: a terminal interface,
an in-process picker, and short-lived clipboard ownership on native X11. The
installable binaries do not provide a Wayland clipboard backend.

> [!CAUTION]
> PVault is pre-alpha software. It has not received an independent security
> audit and may lose or expose data. Do not store real credentials in it.

The current milestone is the Linux desktop application. Android and
synchronization are deliberately out of scope until the local format, recovery
path, and CLI have been exercised and reviewed.

## Design goals

- Keep all record metadata and values inside an authenticated encrypted file.
- Derive a wrapping key from the master password with Argon2id.
- Encrypt with XChaCha20-Poly1305 through libsodium.
- Keep plaintext and keys in locked, explicitly cleared memory where possible.
- Write vault updates atomically and retain encrypted backups.
- Never place passwords or record selectors in command arguments, environment
  variables, or logs. Decrypted record metadata is terminal-only unless the
  user explicitly authorizes a private redirection.
- Keep cryptography, CBOR, and the in-memory model independent of ncurses and
  clipboard code. The current desktop library target still aggregates Linux
  storage, TTY hardening, and XDG configuration; Android will need a small
  platform-interface extraction rather than compiling that target unchanged.

The exact security boundary and known limitations are documented in
[`THREAT_MODEL.md`](THREAT_MODEL.md). The file format is specified in
[`docs/FORMAT.md`](docs/FORMAT.md). Fail-closed version handling, format freeze,
migration, rollback, and rescue rules are defined in
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md).

The complete architecture and four-phase roadmap are available in Portuguese:
[`docs/ARCHITECTURE.pt-BR.md`](docs/ARCHITECTURE.pt-BR.md) and
[`docs/ROADMAP.pt-BR.md`](docs/ROADMAP.pt-BR.md).
Release and reproducibility procedures are in
[`docs/RELEASES.md`](docs/RELEASES.md). The signed A/B/A restore drill is
documented separately in
[`docs/EXTERNAL_RESTORE.md`](docs/EXTERNAL_RESTORE.md).

## Dependencies

Runtime:

- Linux and a C11 runtime
- libsodium 1.0.22 or newer
- libcbor 0.14.0 or newer
- ncursesw
- `xclip` on X11
- `rofi` for the opt-in external picker (optional)

Build:

- CMake 3.24 or newer
- Ninja
- `pkgconf`
- GCC or Clang
- Python 3.10 or newer for compatibility-vector and PTY/clipboard tests
- Git for reproducibility checks and source archives
- OpenSSH for the manual external-restore signatures
- GnuPG for release signing (release maintainers only)

On Arch Linux:

```sh
sudo pacman -S --needed base-devel cmake ninja pkgconf libsodium libcbor ncurses xclip python git openssh gnupg
```

For the optional picker:

```sh
sudo pacman -S --needed rofi
```

The opt-in system test with a real X11 server and real `xclip` additionally
requires `xorg-server-xvfb`. It runs on a disposable display and never touches
the user's current clipboard.

The manual live-i3 canary additionally requires `libxres` so it can bind the
X11 selection Window to the captured local `xclip` PID before its single
synthetic read:

```sh
sudo pacman -S --needed libxres
```

The testing-only Wayland characterization additionally requires `weston` and
`wl-clipboard`. These are not runtime dependencies. The harness starts a
headless disposable compositor and never connects to the user's current
Wayland session:

```sh
sudo pacman -S --needed weston wl-clipboard
```

## Build and test

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

Sanitizer and release presets are also provided:

```sh
cmake --preset asan-ubsan
cmake --build --preset asan-ubsan
ctest --preset asan-ubsan

cmake --preset release
cmake --build --preset release
ctest --preset release
```

Sanitizer builds must only use disposable test vaults. Sanitizers intentionally
copy and inspect memory in ways that are incompatible with production secret
handling. The `asan-ubsan` test preset and the default `ci-build.sh sanitize`
invocation disable LeakSanitizer because managed test environments may deny the
`ptrace` operation it needs. `ci-build.sh` preserves a caller-supplied
`ASAN_OPTIONS`; custom options must include `detect_leaks=0` to retain that
default. The separate `ci-build.sh lsan` profile uses standalone Clang LSan,
keeps `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0`, and therefore requires an
isolated test environment with `CAP_SYS_PTRACE`. Its negative controls must
detect intentional ordinary-heap and guarded-allocator leaks before the real
suite is accepted. The hosted job
grants that capability only inside its disposable LSan container. Test-only
linker wrappers also require every application-visible
`sodium_malloc` to have a matching `sodium_free`, because LSan does not reliably
track libsodium's guarded allocator. No production target or ordinary CI job
receives either exception or wrapper, and CMake refuses to install an LSan
profile.

To install into a staging directory:

```sh
DESTDIR="$PWD/pkg" cmake --install build/release --prefix /usr
```

### CI, fuzzing, and reproducibility

The hosted workflow is optional; portable local scripts are the source of
truth:

```sh
./scripts/ci-build.sh all
./scripts/ci-build.sh lsan      # isolated CAP_SYS_PTRACE test environment
./scripts/fuzz-smoke.sh
./scripts/reproducible-build.sh
./scripts/check-publication.sh
./scripts/restore-drill.sh
./scripts/test-real-x11.sh       # optional; requires Xvfb
./scripts/test-real-wayland.sh   # experimental characterization; not installable support
```

`scripts/test-live-x11-i3.sh` is a separate manual canary for the user's live
native-X11 i3 session. It is never run by CI and requires explicit human
consent because it overwrites the current clipboard. It uses only synthetic
data, does not read, save, or restore the previous clipboard value, and aborts
when it detects a clipboard manager. Its TTL ends PVault's ownership; it cannot
prove revocation or erasure. A first operator-run canary was reported `PASS` at
commit `ca34379`; every release candidate must repeat and review it manually.

```sh
./scripts/test-live-x11-i3.sh --acknowledge-live-clipboard-overwrite
```

The fuzz script keeps synthetic corpora and private failure artifacts under the
Git-ignored `.cache/fuzz/` directory. Never seed it with a real vault. See
[`docs/RELEASES.md`](docs/RELEASES.md) for the release gates and exact
reproducibility boundary.

`restore-drill.sh` creates only synthetic canaries under a disposable mode-0700
directory. It exercises authenticated backup, post-backup mutation, read-only
rescue copy, password/recovery verification, and restore into a separate path;
it fails unless the active vault remains byte-exact throughout rescue.
The separate-machine extension in
[`docs/EXTERNAL_RESTORE.md`](docs/EXTERNAL_RESTORE.md) is implemented but has
not yet produced an accepted receipt from another computer. Its CI parser test
does not close that manual gate.

CTest also runs Linux integration coverage with a real controlling PTY and
deterministic fake X11/Wayland clipboard owners; it does not require an active
display server. A build that intentionally omits these tests can configure with
`-DPVAULT_BUILD_INTEGRATION_TESTS=OFF`.

The separate real-X11 suite is enabled only with
`-DPVAULT_BUILD_X11_SYSTEM_TESTS=ON`. See
[`tests/system/README.md`](tests/system/README.md) for its isolation and threat
boundary.

The separate real-Wayland suite is enabled only with
`-DPVAULT_BUILD_WAYLAND_SYSTEM_TESTS=ON`. It builds non-installable experimental
targets and runs real `wl-copy`/`wl-paste` against headless Weston with
synthetic canaries. A green result deliberately characterizes the unsafe
boundary: Weston can retain and return the canary bytes after owner exit and a
clear request. It therefore does not certify Wayland support, cleanup, or
revocation. Destroying the disposable compositor removes test state as harness
cleanup; it is not a PVault security property.

## Command-line interface

The planned 0.1 interface is:

```text
pvault init [--vault PATH] --recovery-out PATH
pvault add
pvault edit
pvault remove
pvault list [--allow-redirect]
pvault show [--allow-redirect]
pvault copy [--field password|username|url|custom] [--ttl SECONDS]
pvault pick [--copy] [--rofi] [--allow-redirect]
pvault generate [--length N]
pvault passwd [--recovery FILE]
pvault recovery rotate --out PATH
pvault backup --output PATH
pvault restore PATH
pvault rescue inspect SNAPSHOT
pvault rescue verify SNAPSHOT [--recovery FILE] [--allow-redirect]
pvault rescue recover SNAPSHOT --output PATH [--recovery FILE]
pvault rollback SNAPSHOT --output PATH [--recovery FILE]
pvault config check
pvault doctor
pvault shell
```

Run `pvault help` or consult `man pvault` for the commands supported by the
checked-out revision. During pre-alpha development, individual commands may be
landed incrementally.

`edit`, `remove`, `show`, and `copy` select a record with the in-process picker;
they do not accept a title, username, URL, tag, or persistent record ID through
`argv`. The earlier pre-alpha positional forms such as `show QUERY` and
`copy QUERY`, including the old optional filter in `list QUERY`, are
intentionally rejected instead of being reinterpreted. This is a breaking
pre-alpha CLI change made to keep selectors out of shell history and process
arguments. Scripts that parsed the former `Added ID` or `Updated ID` status also
must be updated; those identifiers are no longer emitted.

Do not type a legacy positional selector to test the rejection with real data:
the shell and kernel have already received that argument before PVault can
reject it. Use only synthetic text when checking compatibility errors.

Record metadata is sensitive even when it is not a password. `list`, `show`,
and a non-copying `pick` therefore refuse non-terminal stdout by default.
`rescue verify` applies the same rule to authenticated snapshot identity. The
`--allow-redirect` option is an explicit acknowledgement for a destination the
user has already made private; it does not encrypt, erase, or otherwise protect
that destination. `pick --copy` does not print record metadata and cannot be
combined with `--allow-redirect`. `shell` requires both stdin and stdout to be
terminals.

`show` omits password values and custom fields marked secret. `copy` is the
normal way to retrieve a password. Built-in fields are selected with
`--field password`, `username`, or `url`. `--field custom` lists sanitized
custom-field names on `/dev/tty` and asks for a private ordinal selection, so
duplicate names remain selectable and arbitrary names never enter `argv`.
PVault does not accept a password through `argv` and does not offer a
plaintext password export command. `generate` always offers the generated
password through the clipboard; it never prints it. Successful `add` and
`edit` messages are generic and do not disclose a persistent record ID.

The internal picker is the default. Opting into `--rofi` or configuring
`picker=rofi` sends rofi only a sanitized display title and a random ephemeral
token for that invocation, never the persistent record ID. Rofi is executed
with an allowlisted display/runtime/authentication/locale environment; it is
still an external process that can observe every displayed title.

The installable clipboard path supports `xclip` only when `WAYLAND_DISPLAY` is
empty, `XDG_SESSION_TYPE` is exactly `x11`, and `DISPLAY` is non-empty. Unknown
or missing session metadata fails closed. The direct `copy` and `pick --copy`
flows apply this gate before receiving or decrypting the master password;
`generate` applies it before generating a value. Thus a normal Wayland session
does not silently fall back through XWayland. PVault cannot authenticate what
server a forged `DISPLAY` or spoofed environment identifies; changing these
indicators to bypass the gate is unsupported. Native X11 under i3 is the
current documented path for initial desktop evaluation.

`shell` probes the clipboard backend before unlock, but an unavailable backend
does not prevent a read-only interactive session from opening. Its internal
`copy` action remains unavailable and no secret is sent to a Wayland or
XWayland owner.

The `wl-copy` owner and best-effort clear implementation is compiled only into
explicit experimental test targets that CMake does not install. The Weston
characterization reproduces retention of the synthetic bytes after owner exit
and a clear request. Its green status records that limitation; it is not a
claim that the clipboard was erased or revoked. Even on X11, a client or
clipboard manager can retain a value it has already requested, so TTL limits
ownership rather than providing strong revocation.

`passwd` normally authenticates with the current master password. With
`--recovery FILE`, it reads the recovery key from FILE and allows a new master
password to be set without changing the random vault master key. The recovery
key itself is never accepted through `argv`.

New master passwords use one shared guardrail in both `init` and `passwd`: at
least 16 bytes, with conspicuously common values, full keyboard/numeric/alphabet
sequences, and periodic repetitions rejected. This filter is not an entropy
estimator and cannot make a chosen password strong. Prefer a unique passphrase
of 5-6 words selected by a cryptographically secure generator and keep it
separate from the recovery key.

Restore replaces the complete encrypted snapshot, including its password and
recovery keyslots. Keep historical credentials until the restored vault has
been authenticated and a fresh recovery key has been stored offline. If an
active vault exists, its vault ID must match the authenticated backup;
cross-vault replacement requires a future explicit import workflow. The active
ID is the declared cleartext header value, so this lineage guard does not prove
that a damaged active snapshot can still authenticate.

`rescue inspect` performs framing and private-file checks only. Every value it
prints is explicitly marked unauthenticated. `rescue verify` requires either a
master password from the TTY or a recovery file, authenticates the complete
AEAD body, parses canonical CBOR, and prints only version, vault ID, generation,
record count, and the encrypted snapshot hash. It never prints record fields,
and redirected output requires `--allow-redirect`.

`rescue recover` authenticates first, then publishes a byte-exact encrypted copy
at a new path with no-replace semantics, mode 0400, file/directory `fsync()`, and
readback verification. `rollback` is the same safe copy primitive with
application-rollback wording: it never replaces the active vault. Use `restore`
only for the separate, explicit operation that rolls the active data back.

There is intentionally no cross-version migration command yet. Format 1.0 is
the first and only implemented format; rewriting 1.0 as 1.0 would be a repack,
not a migration. A real migrator will ship with the first specified successor
format and will require its own N-1 fixture, transactional backup, recovery-key
policy, and lossless transformation tests.

### i3 example

After installing PVault, add a binding such as this to the i3 configuration:

```text
bindsym $mod+p exec --no-startup-id alacritty -e pvault copy
```

Use your preferred terminal in place of `alacritty`. PVault does not edit the
i3 configuration automatically.

## Configuration

The optional configuration file uses strict `key=value` lines. Blank lines and
lines whose first non-space character is `#` are ignored; unknown keys, invalid
values, duplicate keys, embedded NUL bytes, oversized files or lines, and
relative vault paths are rejected. CRLF and LF line endings are accepted. The
file is parsed transactionally, so an invalid later line cannot leave earlier
values partially applied. It is not a place for passwords or other secrets.

When the file exists it must be a regular, non-symlink file owned by the current
user, have exactly one hard link, and use mode `0600` or `0400`. Its immediate
parent must also be owned by the current user and must not be group/world
writable. PVault opens the parent and file by descriptor with `O_NOFOLLOW` and
validates metadata before reading; FIFOs and device files are rejected without
interpretation, and `O_NONBLOCK` prevents a FIFO from stalling the process. A
missing file under an absent or valid immediate parent continues to select the
built-in defaults; an unsafe existing parent fails closed even when the file is
absent.

| Key | Accepted value | Default |
| --- | --- | --- |
| `vault_path` | Absolute path | XDG data path shown below |
| `clipboard_ttl_seconds` | Integer from 1 to 300 | `10` |
| `session_idle_seconds` | Integer from 30 to 86400 | `300` |
| `backup_retention` | Integer from 1 to 1000 | `20` |
| `picker` | `internal` or `rofi` | `internal` |

For example:

```ini
clipboard_ttl_seconds=10
session_idle_seconds=300
backup_retention=20
picker=internal
```

## Local files

By default PVault uses:

```text
$XDG_DATA_HOME/pvault/vault.pvlt
$XDG_DATA_HOME/pvault/backups/
$XDG_CONFIG_HOME/pvault/config
```

If you create the optional file manually, use `chmod 600` on it. A mode such as
`0644` is rejected even though the current keys are not secrets, because the
configuration controls the selected vault, retention behavior, clipboard TTL,
and external-picker opt-in.
If upgrading from an earlier pre-alpha revision that accepted `0644`, run
`chmod 600 "${XDG_CONFIG_HOME:-$HOME/.config}/pvault/config"` before the next
normal command.

Run `pvault config check` to validate either the private file or the built-in
defaults. The command deliberately loads configuration itself, so it still
runs when normal commands reject an invalid file. It reports no configured
paths or values.

If the XDG variables are unset, their standard defaults below `$HOME` are used.
The recovery file created by `init` must be moved to separate offline storage;
keeping it beside the vault defeats its recovery purpose.

For a custom vault path, automatic encrypted snapshots are stored in a literal
`backups/` directory beside the vault. For example, `/safe/pvault/main.pvlt`
uses `/safe/pvault/backups/`. PVault rejects a symlink or foreign-owned backup
directory and may normalize an existing owner-owned directory to mode 0700.
Use a dedicated parent directory for a custom vault to avoid colliding with an
unrelated directory already named `backups`.

PVault never changes permissions on an existing parent such as `$HOME` or a
project directory. The vault's immediate parent must be owned by the current
user and must not be group/world-writable; create a dedicated mode-0700
directory or correct it explicitly if an operation reports an I/O error. A
write transaction holds that immediate-parent directory descriptor from lock
acquisition through commit and readback, addresses the lock, temporary file,
vault, and automatic backups relative to it, and rechecks the configured
pathname before and after publication. This confines a moved-parent race to the
opened directory, but it does not make an otherwise untrusted ancestor or a
compromised Unix account safe.

Every vault or encrypted snapshot consumed by PVault must be a regular,
non-symlink file owned by the current user, with exactly one hard link and mode
`0400` or `0600`. PVault-created files remain `0600`; `0400` permits a deliberate
read-only backup. A `0400` snapshot can be opened, copied, and restored, but
cannot be saved in place. An automatic backup changed to `0400` is pinned and
excluded from retention; a normally managed automatic backup remains `0600`.
A snapshot copied from FAT/exFAT, a foreign-owned mount, or other storage
without trustworthy POSIX ownership/link/mode semantics must first be copied
into a private local directory and set to `0600` before restore.

Automatic backups use
`auto-v1-<32-lowercase-vault-id>-g<20-digit-generation>.pvlt`. Retention is
numeric, per vault ID, and runs only after the replacement snapshot has been
committed and verified. Before an entry becomes eligible, PVault authenticates
its AEAD body, parses its CBOR payload, and requires the internal generation to
match the filename. It never removes pinned `0400` snapshots, manual or legacy names,
`pre-restore-*`, `pre-migrate-*`, another vault's files, future generations, or
near-matches. A suspicious managed-name entry stops that pruning pass and is
left untouched; excess encrypted backups are safer than deleting an uncertain
file. New automatic and manual backups are first written and synchronized under
a private temporary name, then published atomically without replacing an
existing entry; a crash cannot leave a partial deterministic backup name that
blocks every retry.

If `init` commits the vault but cannot create the requested recovery file, it
keeps the empty vault instead of deleting a possibly durable commit. Use the
master password immediately with `pvault recovery rotate --out PATH` before
adding any records.

Do not synchronize a live vault with tools that resolve concurrent edits by
silently choosing one file. Multi-device synchronization is not part of 0.1.

## Open-source development

PVault is licensed under `GPL-3.0-or-later`. Contributions are welcome, but
cryptography, parsers, secure-memory code, persistence, recovery, and clipboard
changes require especially careful review. Read [`CONTRIBUTING.md`](CONTRIBUTING.md)
before submitting a change and report security issues according to
[`SECURITY.md`](SECURITY.md).

Copyright is held by the individual PVault contributors; the repository-level
notice is in [`COPYRIGHT`](COPYRIGHT).
