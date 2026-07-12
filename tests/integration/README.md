# CLI security integration tests

These tests exercise real controlling-terminal, signal, and clipboard process
behavior. They use only Python's standard library and disposable directories
below `/tmp`. Clipboard tests compile an isolated driver and `pvault-clip`
helper with compile-time paths to a deterministic fake owner; production builds
continue to use the absolute `/usr/bin/xclip` and `/usr/bin/wl-copy` paths.

Build PVault first, then run:

```sh
cmake --preset debug
cmake --build --preset debug
python3 tests/integration/run.py
```

Set `PVAULT_BUILD_DIR` to test another build directory. The suite never puts a
secret in argv or the environment. The fake clipboard owner persists only the
secret length and SHA-256 digest plus boolean leakage checks; it never writes
the received secret or complete environment/cmdline data to disk.

Tests using the real `/usr/bin/xclip` live separately under `tests/system/` and
are opt-in, so the default suite never touches a user's clipboard or requires
an X server.
