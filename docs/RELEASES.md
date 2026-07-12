# Reproducible builds and release procedure

PVault is pre-alpha. Passing this procedure proves that a revision builds and
tests consistently in the exercised environment; it does not constitute a
security audit or approval for real credentials.

## Version convention

The numeric project/package/tag version is currently `0.1.0`. `pre-alpha` is a
separate maturity label shown by the CLI and man page; it is not an additional
Arch `pkgver` component. Release review must compare both the numeric version
and the maturity label independently. Tags and source archive prefixes use the
numeric form, such as `v0.1.0` and `pvault-0.1.0/`.

The application version is independent of the file-format version. The current
application writes the pre-alpha format v1.0 draft; an application release does
not freeze or increment that format implicitly. Format freeze, compatibility,
migration, rollback, and rescue follow
[`COMPATIBILITY.md`](COMPATIBILITY.md).

## Local verification entry points

The repository-host workflow is optional. These local scripts are the source of
truth and can run on a self-hosted runner or another forge:

```sh
./scripts/ci-build.sh gcc
./scripts/ci-build.sh clang
./scripts/ci-build.sh sanitize
./scripts/ci-build.sh release
./scripts/fuzz-smoke.sh
./scripts/reproducible-build.sh
./scripts/check-publication.sh
./scripts/restore-drill.sh
./scripts/test-real-x11.sh
```

`ci-build.sh all` runs the four build profiles sequentially. The build/test and
reproducibility scripts require Python 3.10 or newer because the CTest
integration suite drives PTYs and mock clipboard processes without requiring a
real X11 or Wayland display. The reproducibility and archive procedures also
require Git. Creating signed tags and checksum files requires GnuPG; it is not a
normal build dependency.

The last command is an opt-in X11 system test and requires `Xvfb` (the
`xorg-server-xvfb` package on Arch). It starts a private display and invokes the
real `/usr/bin/xclip`; it does not connect to the user's current X11 session.

The checked-in hosted workflow currently covers x86-64 Arch Linux with glibc.
It does not claim ARM64, musl, another distribution, or another kernel. Those
cross-platform jobs remain a roadmap gate; the local scripts are intentionally
independent of the repository host so equivalent runners can call them later.

The CMake sanitizer test preset and the default `ci-build.sh sanitize`
invocation disable LeakSanitizer in the normal hardened test process.
`ci-build.sh` preserves a caller-supplied `ASAN_OPTIONS`, so a custom value must
include `detect_leaks=0` to retain that default. Before a release, run a separate
leak check on a trusted host that permits the required tracing and use synthetic
fixtures only.

## Fuzz state

The smoke script builds all Clang/libFuzzer targets and defaults to 2,000 inputs
per target. Override the bounded run and persistent state directory with:

```sh
PVAULT_FUZZ_RUNS=100000 \
PVAULT_FUZZ_STATE_DIR="$HOME/.cache/pvault-fuzz" \
    ./scripts/fuzz-smoke.sh
```

Corpora evolve under `corpus/<target>` and failure artifacts are isolated under
`artifacts/<target>`. New directories are created mode 0700 under a mode-077
umask. A user-supplied existing state directory must already be non-symlinked,
owned by that user, owner-readable/writable/searchable, and inaccessible to
group/other; the script never changes its permissions. Corpora must contain
only synthetic inputs. Treat an
unexplained crash artifact as potentially sensitive and follow `SECURITY.md`;
do not upload it automatically from CI.

A smoke run is a regression tripwire, not continuous fuzzing. A release
candidate should additionally receive a long-running campaign on every parser,
followed by corpus minimization and private triage of all artifacts.

## Reproducibility check

`reproducible-build.sh` performs two clean Release builds, runs both test suites,
installs each into an independent staging root, and compares a sorted manifest
of file types, modes, paths, and SHA-256 content hashes. It fixes locale,
timezone, archive date behavior, source epoch, compiler path maps, and linker
build-ID policy.

The check intentionally ignores filesystem ownership and mtime in staging.
Release archives must normalize those attributes separately. Run the check in a
documented, pinned build environment and record at least:

```sh
gcc --version
cmake --version
ninja --version
pkg-config --modversion libsodium libcbor ncursesw
uname -a
```

Two matching outputs produced on the same host are necessary but insufficient.
Before claiming cross-builder reproducibility, compare manifests from at least
two independent clean hosts using the same declared toolchain/dependency set.

## Format compatibility gate

A release that claims a frozen format must bind its signed tag to the normative
format document, byte-exact conformance vectors, and the compatibility contract.
Format v1.0 remains a draft until every freeze criterion in
`COMPATIBILITY.md` is met.

A release that first writes a newer stable format must additionally test the
documented `N-1` writer, all frozen historical read fixtures, explicit
transactional migration, pre-migration backup outside normal retention,
rollback, and rescue procedures. Ordinary open must remain read-only with
respect to older formats; unsupported versions must fail closed. Migration or
rescue artifacts must never contain real credentials.

## Release gate

1. Run `scripts/check-publication.sh`, confirm the tree is clean, and review
   every staged path.
2. Confirm the application version in CMake, the public header, PKGBUILD, tag,
   and archive agree; separately confirm the CLI, man page, and README use the
   intended maturity label and that the declared file-format status/version is
   accurate.
3. Run all four CI profiles and the reproducibility check from a clean clone.
4. Run the extended fuzz campaign and privately resolve every crash.
5. Run `scripts/restore-drill.sh`, then exercise init, mutation, backup,
   password/recovery rotation, rescue/rollback copy, and restore with synthetic
   data on a separate machine.
6. Review `THREAT_MODEL.md`, `SECURITY.md`, `FORMAT.md`, `COMPATIBILITY.md`,
   dependencies, and format vectors. If the release freezes or changes a format,
   satisfy the format compatibility gate above.
7. Create a signed annotated tag such as `v0.1.0`.
8. Generate the source archive from that tag, compute SHA-256, and sign the
   checksum file with the project's published release key.
9. Replace the development PKGBUILD's local archive, absent upstream URL, and
   `SKIP` checksum with the immutable release URL and real SHA-256 digest.
10. Have an independent maintainer rebuild and compare before publication.

Example archive commands after the signed tag exists:

```sh
version=0.1.0
git verify-tag "v$version"
git archive --format=tar.gz --prefix="pvault-$version/" \
    --output="pvault-$version.tar.gz" "v$version"
sha256sum "pvault-$version.tar.gz" > SHA256SUMS
gpg --armor --detach-sign SHA256SUMS
```

Do not publish the private signing key, fuzz artifacts, test recovery files, or
local vaults as workflow artifacts. A 0.x release remains explicitly
experimental until the audit and recovery gates in the roadmap are complete.
