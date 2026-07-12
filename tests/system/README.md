# Opt-in system tests

These tests exercise operating-system integrations that the default headless
CTest suite replaces with deterministic fakes. They are disabled unless their
corresponding CMake option is explicitly enabled.

## Real X11 clipboard

The X11 suite starts an authenticated, disposable `Xvfb` server and invokes the
real `/usr/bin/xclip`. It never connects to the user's current `DISPLAY`, so it
does not read, replace, or log the personal clipboard. Test values are random,
synthetic ASCII canaries sent to PVault over stdin.

On Arch Linux, install the additional test dependency and run:

```sh
sudo pacman -S --needed xorg-server-xvfb
./scripts/test-real-x11.sh
```

For a bounded race/repetition check:

```sh
PVAULT_X11_REPEAT=20 ./scripts/test-real-x11.sh
```

The suite verifies a real X11 selection round-trip, TTL expiration, process
reaping, and `PR_SET_PDEATHSIG` cleanup after killing the clipboard supervisor.
It also checks that the synthetic canary is absent from argv, the environment,
stdout, and stderr. Failure diagnostics contain only sizes, hashes, process
identities, and timing information.

This does not model a clipboard manager. A manager can copy and retain a secret
before expiration; PVault cannot revoke data already consumed by another
process. Manual testing on the user's live display must remain a separate,
explicit operation because claiming `CLIPBOARD` replaces its current contents.
