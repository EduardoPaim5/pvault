# PVault

PVault is an experimental, local-first password vault for Linux, written in
C11. It is designed for a keyboard-driven workflow: a terminal interface,
an in-process picker, and short-lived clipboard ownership on X11 or Wayland.

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
- Never place passwords in command arguments, environment variables, logs, or
  normal terminal output.
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
[`docs/RELEASES.md`](docs/RELEASES.md).

## Dependencies

Runtime:

- Linux and a C11 runtime
- libsodium 1.0.22 or newer
- libcbor 0.14.0 or newer
- ncursesw
- `xclip` on X11
- `wl-clipboard` on Wayland (optional)
- `rofi` for the opt-in external picker (optional)

Build:

- CMake 3.24 or newer
- Ninja
- `pkgconf`
- GCC or Clang
- Python 3.10 or newer for compatibility-vector and PTY/clipboard tests
- Git for reproducibility checks and source archives
- GnuPG for release signing (release maintainers only)

On Arch Linux:

```sh
sudo pacman -S --needed base-devel cmake ninja pkgconf libsodium libcbor ncurses xclip python git gnupg
```

For Wayland and the optional picker:

```sh
sudo pacman -S --needed wl-clipboard rofi
```

The opt-in system test with a real X11 server and real `xclip` additionally
requires `xorg-server-xvfb`. It runs on a disposable display and never touches
the user's current clipboard.

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
default. Leak checks remain required before release and must run separately on
a `ptrace`-capable host, with test-process hardening adjusted only for that run.

To install into a staging directory:

```sh
DESTDIR="$PWD/pkg" cmake --install build/release --prefix /usr
```

### CI, fuzzing, and reproducibility

The hosted workflow is optional; portable local scripts are the source of
truth:

```sh
./scripts/ci-build.sh all
./scripts/fuzz-smoke.sh
./scripts/reproducible-build.sh
./scripts/check-publication.sh
./scripts/test-real-x11.sh       # optional; requires Xvfb
```

The fuzz script keeps synthetic corpora and private failure artifacts under the
Git-ignored `.cache/fuzz/` directory. Never seed it with a real vault. See
[`docs/RELEASES.md`](docs/RELEASES.md) for the release gates and exact
reproducibility boundary.

CTest also runs Linux integration coverage with a real controlling PTY and
deterministic fake X11/Wayland clipboard owners; it does not require an active
display server. A build that intentionally omits these tests can configure with
`-DPVAULT_BUILD_INTEGRATION_TESTS=OFF`.

The separate real-X11 suite is enabled only with
`-DPVAULT_BUILD_X11_SYSTEM_TESTS=ON`. See
[`tests/system/README.md`](tests/system/README.md) for its isolation and threat
boundary.

## Command-line interface

The planned 0.1 interface is:

```text
pvault init [--vault PATH] --recovery-out PATH
pvault add
pvault edit QUERY
pvault remove QUERY
pvault list [QUERY]
pvault show QUERY
pvault copy QUERY [--field FIELD] [--ttl SECONDS]
pvault pick [--copy] [--rofi]
pvault generate [--length N]
pvault passwd [--recovery FILE]
pvault recovery rotate --out PATH
pvault backup --output PATH
pvault restore PATH
pvault doctor
pvault shell
```

Run `pvault help` or consult `man pvault` for the commands supported by the
checked-out revision. During pre-alpha development, individual commands may be
landed incrementally.

`show` intentionally omits secret values. `copy` is the normal way to retrieve
a password. PVault does not accept a password through `argv` and does not offer
a plaintext export command. `generate` always offers the generated password
through the clipboard; it never prints it.

`passwd` normally authenticates with the current master password. With
`--recovery FILE`, it reads the recovery key from FILE and allows a new master
password to be set without changing the random vault master key. The recovery
key itself is never accepted through `argv`.

Restore replaces the complete encrypted snapshot, including its password and
recovery keyslots. Keep historical credentials until the restored vault has
been authenticated and a fresh recovery key has been stored offline. If an
active vault exists, its vault ID must match the authenticated backup;
cross-vault replacement requires a future explicit import workflow. The active
ID is the declared cleartext header value, so this lineage guard does not prove
that a damaged active snapshot can still authenticate.

### i3 example

After installing PVault, add a binding such as this to the i3 configuration:

```text
bindsym $mod+p exec --no-startup-id alacritty -e pvault pick --copy
```

Use your preferred terminal in place of `alacritty`. PVault does not edit the
i3 configuration automatically.

## Configuration

The optional configuration file uses strict `key=value` lines. Blank lines and
lines whose first non-space character is `#` are ignored; unknown keys, invalid
values, and relative vault paths are rejected. It is not a place for passwords
or other secrets.

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
