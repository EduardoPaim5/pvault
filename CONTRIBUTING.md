# Contributing to PVault

PVault welcomes review, tests, documentation, and carefully scoped code changes.
It is security-sensitive pre-alpha software: favor small, auditable changes over
large rewrites and never test with real credentials.

## Development environment

On Arch Linux, install:

```sh
sudo pacman -S --needed base-devel cmake ninja pkgconf libsodium libcbor ncurses xclip clang python git
```

The integration suite requires Python 3.10 or newer. Release maintainers also
need GnuPG for signed tags and checksum files.

Changes to the X11 clipboard process should also install
`xorg-server-xvfb` and run `./scripts/test-real-x11.sh`; this suite uses a
disposable display rather than the contributor's live clipboard.

Then run the same local entry point used by hosted CI:

```sh
./scripts/ci-build.sh all
```

Before staging or publishing a change, run `./scripts/check-publication.sh`.
It rejects vaults, lock/recovery files, dumps, common private-key/token shapes,
and absolute user-home paths without printing matching contents.

Do not run sanitizer or fuzzer builds against a real vault. Use generated,
disposable fixtures containing synthetic values only.

## Change expectations

- Follow C11 without compiler extensions.
- Preserve warning-clean builds under GCC and Clang.
- Use checked arithmetic and explicit lengths for untrusted data.
- Do not implement cryptographic primitives; use the approved libsodium APIs.
- Do not put a secret in `argv`, the environment, stdout, logs, a temporary file,
  a process title, or a shell command.
- Do not write C structs directly to disk. Update `docs/FORMAT.md`, version gates,
  fixtures, and tests for every format change.
- Keep cryptography, CBOR, and the in-memory model decoupled from
  platform-specific TTY, filesystem, process, and clipboard behavior. Extracting
  the Linux modules from the current aggregate `pvault_core` target is a roadmap
  objective; do not introduce new platform dependencies into the portable
  modules in the meantime.
- Route failures through cleanup that is safe when partially initialized.
- Avoid unnecessary secret copies, especially on the stack or ordinary heap.

Changes to cryptography, parsing, secure memory, persistence, recovery, or the
clipboard should include focused negative tests and receive two-person review
when the project has enough maintainers. A format change must include migration
or explicit rejection behavior; silent reinterpretation is forbidden.

## Tests

At minimum, a change should run:

```sh
ctest --preset debug
ctest --preset asan-ubsan
```

Parser and format work should also build the Clang fuzz preset and exercise the
relevant corpus:

```sh
./scripts/fuzz-smoke.sh
```

The evolving corpus and private failure artifacts are kept under `.cache/fuzz/`
and must contain synthetic inputs only. See `docs/RELEASES.md` before retaining,
sharing, minimizing, or publishing a crashing input.

Tests must cover failure paths as well as the happy path. Useful cases include
truncation, bit flips, unknown versions, extreme lengths, allocation failure,
wrong credentials, concurrent writers, interrupted saves, and clipboard-owner
races.

## Submitting changes

1. Keep each commit buildable and limited to one purpose.
2. Explain the threat or user problem being addressed.
3. State the exact tests run and compiler versions used.
4. Call out file-format, compatibility, memory-lifetime, and recovery effects.
5. Never attach a real vault, master password, recovery key, or memory dump.

Security vulnerabilities follow `SECURITY.md`, not the normal public review
process.

By contributing, you agree that your contribution is licensed under the
project's `GPL-3.0-or-later` license.
