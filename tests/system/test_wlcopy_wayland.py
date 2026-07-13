#!/usr/bin/env python3
"""Opt-in system tests using headless Weston and the real wl-copy/wl-paste."""

from __future__ import annotations

import hashlib
import os
import secrets
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


REPOSITORY = Path(__file__).resolve().parents[2]
INTEGRATION_DIRECTORY = REPOSITORY / "tests" / "integration"
sys.path.insert(0, str(INTEGRATION_DIRECTORY))

from pty_harness import process_file, process_starttime, wait_until  # noqa: E402


DRIVER = Path(os.environ["PVAULT_WAYLAND_DRIVER"]).resolve()
WESTON = Path(os.environ["PVAULT_WESTON"]).resolve()
WL_COPY = Path(os.environ["PVAULT_WL_COPY"]).resolve()
WL_PASTE = Path(os.environ["PVAULT_WL_PASTE"]).resolve()
TEXT_MIME = "text/plain;charset=utf-8"


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    starttime: bytes


@dataclass(frozen=True)
class WaylandContext:
    root: Path
    environment: dict[str, str]
    server: subprocess.Popen[bytes]


def safe_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def process_ppid(pid: int) -> int | None:
    stat = process_file(pid, "stat")
    if stat is None:
        return None
    command_end = stat.rfind(b")")
    if command_end < 0:
        return None
    fields = stat[command_end + 1 :].split()
    if len(fields) < 2:
        return None
    try:
        return int(fields[1])
    except ValueError:
        return None


def identity(pid: int) -> ProcessIdentity | None:
    starttime = process_starttime(pid)
    return None if starttime is None else ProcessIdentity(pid, starttime)


def identity_exists(process: ProcessIdentity) -> bool:
    return process_starttime(process.pid) == process.starttime


def signal_identity(process: ProcessIdentity, signal_number: int) -> bool:
    try:
        pidfd = os.pidfd_open(process.pid, 0)
    except (AttributeError, OSError, ProcessLookupError):
        return False
    try:
        if not identity_exists(process):
            return False
        signal.pidfd_send_signal(pidfd, signal_number)
        return True
    except (AttributeError, OSError, ProcessLookupError):
        return False
    finally:
        os.close(pidfd)


def paste(environment: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [WL_PASTE, "--no-newline", "--type", TEXT_MIME],
        cwd=REPOSITORY,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3.0,
        check=False,
    )


def selection_types(environment: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [WL_PASTE, "--list-types"],
        cwd=REPOSITORY,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3.0,
        check=False,
    )


def wait_for_secret(
    environment: dict[str, str], secret: bytes, timeout: float = 4.0
) -> None:
    deadline = time.monotonic() + timeout
    last_returncode: int | None = None
    last_length = 0
    last_digest = ""
    while time.monotonic() < deadline:
        completed = paste(environment)
        last_returncode = completed.returncode
        last_length = len(completed.stdout)
        last_digest = safe_digest(completed.stdout)
        if completed.returncode == 0 and completed.stdout == secret:
            return
        time.sleep(0.02)
    raise AssertionError(
        "real wl-paste never returned the synthetic canary; "
        f"returncode={last_returncode}, length={last_length}, sha256={last_digest}"
    )


def find_wlcopy_child(supervisor: int) -> ProcessIdentity | None:
    expected = [
        b"wl-copy",
        b"--foreground",
        b"--type",
        TEXT_MIME.encode("ascii"),
    ]
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if process_ppid(pid) != supervisor:
            continue
        command = process_file(pid, "cmdline")
        if command is None or command.rstrip(b"\0").split(b"\0") != expected:
            continue
        found = identity(pid)
        if found is not None:
            return found
    return None


@contextmanager
def isolated_wayland_server() -> Iterator[WaylandContext]:
    with tempfile.TemporaryDirectory(prefix="pvault-real-wayland-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        home = root / "home"
        runtime = root / "runtime"
        home.mkdir(mode=0o700)
        runtime.mkdir(mode=0o700)
        socket_name = f"wayland-pvault-{secrets.token_hex(8)}"
        log_path = root / "weston.log"
        environment = {
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "WAYLAND_DISPLAY": socket_name,
            "XDG_RUNTIME_DIR": str(runtime),
        }
        for name in ("ASAN_OPTIONS", "LSAN_OPTIONS", "UBSAN_OPTIONS"):
            value = os.environ.get(name)
            if value:
                environment[name] = value
        server = subprocess.Popen(
            [
                WESTON,
                "--backend=headless",
                "--renderer=noop",
                f"--socket={socket_name}",
                "--no-config",
                "--fake-seat",
                "--idle-time=0",
                f"--log={log_path}",
            ],
            cwd=REPOSITORY,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline and server.poll() is None:
                if (runtime / socket_name).is_socket():
                    try:
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                            probe.settimeout(0.25)
                            probe.connect(str(runtime / socket_name))
                        break
                    except OSError:
                        pass
                time.sleep(0.05)
            else:
                raise RuntimeError("could not start a disposable headless Weston server")
            initial = selection_types(environment)
            if initial.returncode == 0 and initial.stdout != b"":
                raise RuntimeError("disposable Wayland session did not start with an empty selection")
            yield WaylandContext(root, environment, server)
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=2.0)


class RealWlCopyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.supervisors: list[ProcessIdentity] = []
        self.auxiliary_processes: list[subprocess.Popen[bytes]] = []
        self.wayland_server = isolated_wayland_server()
        self.context = self.wayland_server.__enter__()
        self.addCleanup(self.wayland_server.__exit__, None, None, None)

    def tearDown(self) -> None:
        supervisor_cleanup_failed = False

        for supervisor in self.supervisors:
            if identity_exists(supervisor):
                signal_identity(supervisor, signal.SIGKILL)
        for supervisor in self.supervisors:
            try:
                wait_until(
                    lambda item=supervisor: not identity_exists(item),
                    4.0,
                    "real Wayland clipboard supervisor cleanup",
                )
            except AssertionError:
                supervisor_cleanup_failed = (
                    identity_exists(supervisor) or supervisor_cleanup_failed
                )

        for process in self.auxiliary_processes:
            if process.poll() is None:
                process.terminate()
        for process in self.auxiliary_processes:
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
            try:
                process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)

        if supervisor_cleanup_failed:
            self.fail("Wayland clipboard supervisor survived identity-safe cleanup")

    def assert_secret_absent(self, secret: bytes, contents: bytes, location: str) -> None:
        self.assertTrue(
            secret not in contents,
            f"synthetic canary reached {location}; content_length={len(contents)}, "
            f"sha256={safe_digest(contents)}",
        )

    def send_secret(self, secret: bytes, ttl: int) -> ProcessIdentity:
        invocation = [DRIVER, "send", str(ttl)]
        invocation_blob = b"\0".join(os.fsencode(value) for value in invocation)
        environment_blob = b"\0".join(
            os.fsencode(key) + b"=" + os.fsencode(value)
            for key, value in self.context.environment.items()
        )
        self.assert_secret_absent(secret, invocation_blob, "driver argv")
        self.assert_secret_absent(secret, environment_blob, "driver environment")
        process = subprocess.Popen(
            invocation,
            cwd=REPOSITORY,
            env=self.context.environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            self.assertIsNotNone(process.stdout)
            assert process.stdout is not None
            readable, _, _ = select.select([process.stdout], [], [], 8.0)
            self.assertTrue(readable, "real Wayland driver did not finish preparation")
            first_line = process.stdout.readline()
            self.assertTrue(first_line.startswith(b"SUPERVISOR "))
            supervisor = identity(int(first_line.split(maxsplit=1)[1]))
            self.assertIsNotNone(supervisor)
            assert supervisor is not None
            self.supervisors.append(supervisor)
            for name in ("cmdline", "environ"):
                contents = process_file(process.pid, name)
                if contents is not None:
                    self.assert_secret_absent(secret, contents, f"driver {name}")
            stdout, stderr = process.communicate(input=secret, timeout=8.0)
            diagnostics = first_line + stdout + stderr
            self.assertEqual(
                0,
                process.returncode,
                "real Wayland driver failed; "
                f"output_length={len(diagnostics)}, sha256={safe_digest(diagnostics)}",
            )
            self.assert_secret_absent(secret, diagnostics, "driver diagnostics")
            return supervisor
        except BaseException:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=2.0)
            raise

    def start_replacement(self, secret: bytes) -> tuple[subprocess.Popen[bytes], ProcessIdentity]:
        invocation = [WL_COPY, "--foreground", "--type", TEXT_MIME]
        invocation_blob = b"\0".join(os.fsencode(value) for value in invocation)
        environment_blob = b"\0".join(
            os.fsencode(key) + b"=" + os.fsencode(value)
            for key, value in self.context.environment.items()
        )
        self.assert_secret_absent(secret, invocation_blob, "replacement argv")
        self.assert_secret_absent(secret, environment_blob, "replacement environment")
        process = subprocess.Popen(
            invocation,
            cwd=REPOSITORY,
            env=self.context.environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.auxiliary_processes.append(process)
        replacement = identity(process.pid)
        self.assertIsNotNone(replacement)
        assert replacement is not None
        try:
            self.assertIsNotNone(process.stdin)
            assert process.stdin is not None
            process.stdin.write(secret)
            process.stdin.close()
            wait_for_secret(self.context.environment, secret)
            self.assertTrue(identity_exists(replacement))
            return process, replacement
        except BaseException:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2.0)
            raise

    def test_characterization_ttl_clear_retains_weston_cache(self) -> None:
        secret = f"PVAULT-WAYLAND-TTL-{secrets.token_hex(16)}".encode("ascii")
        started = time.monotonic()
        supervisor = self.send_secret(secret, 2)
        wait_for_secret(self.context.environment, secret)
        owner = find_wlcopy_child(supervisor.pid)
        self.assertIsNotNone(owner)
        assert owner is not None
        wait_until(lambda: not identity_exists(owner), 6.0, "real wl-copy TTL exit")
        wait_until(
            lambda: not identity_exists(supervisor),
            6.0,
            "real Wayland clipboard supervisor TTL exit",
        )

        # Invoke and verify a second, explicit clear so this characterization
        # cannot pass merely because the experimental supervisor failed to
        # spawn its internal best-effort clear.  Weston still retains the
        # payload.  Green means the hazard was reproduced, not revocation.
        explicit_clear = subprocess.run(
            [WL_COPY, "--clear"],
            cwd=REPOSITORY,
            env=self.context.environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3.0,
            check=False,
        )
        self.assertEqual(
            0,
            explicit_clear.returncode,
            "explicit characterization clear failed; "
            f"stderr_length={len(explicit_clear.stderr)}, "
            f"sha256={safe_digest(explicit_clear.stderr)}",
        )
        retained = paste(self.context.environment)
        self.assertTrue(
            retained.returncode == 0 and retained.stdout == secret,
            "known Weston retention hazard was not reproduced; review the "
            "characterization instead of treating this as revocation; "
            f"returncode={retained.returncode}, output_length={len(retained.stdout)}, "
            f"sha256={safe_digest(retained.stdout)}",
        )
        self.assertGreaterEqual(time.monotonic() - started, 1.5)

    def test_real_wlcopy_dies_with_killed_supervisor(self) -> None:
        secret = f"PVAULT-WAYLAND-PDEATH-{secrets.token_hex(16)}".encode("ascii")
        supervisor = self.send_secret(secret, 30)
        wait_for_secret(self.context.environment, secret)
        owner = find_wlcopy_child(supervisor.pid)
        self.assertIsNotNone(owner)
        assert owner is not None
        self.assertTrue(signal_identity(supervisor, signal.SIGKILL))
        wait_until(
            lambda: not identity_exists(supervisor),
            4.0,
            "killed real Wayland clipboard supervisor",
        )
        wait_until(lambda: not identity_exists(owner), 4.0, "real wl-copy parent-death exit")
        self.assertIsNone(
            self.context.server.poll(),
            "disposable Weston exited, so owner death cannot prove PDEATHSIG",
        )

        # Weston may cache the selection after an abrupt owner death.  This
        # test proves the PDEATHSIG process boundary only.  Observing a cached
        # value is allowed; destroying this test's compositor is the cleanup.
        observed = paste(self.context.environment)
        if observed.returncode == 0 and observed.stdout != b"":
            self.assertTrue(
                observed.stdout == secret,
                "disposable compositor returned an unexpected cached payload; "
                f"output_length={len(observed.stdout)}, "
                f"sha256={safe_digest(observed.stdout)}",
            )

    def test_real_wlcopy_replacement_survives_original_ttl(self) -> None:
        original = f"PVAULT-WAYLAND-ORIGINAL-{secrets.token_hex(16)}".encode("ascii")
        replacement = f"PVAULT-WAYLAND-REPLACEMENT-{secrets.token_hex(16)}".encode("ascii")
        ttl = 2
        supervisor = self.send_secret(original, ttl)
        accepted_at = time.monotonic()
        wait_for_secret(self.context.environment, original)
        owner = find_wlcopy_child(supervisor.pid)
        self.assertIsNotNone(owner)
        assert owner is not None

        replacement_process, replacement_identity = self.start_replacement(replacement)
        wait_until(lambda: not identity_exists(owner), 4.0, "replaced wl-copy owner exit")
        wait_until(
            lambda: not identity_exists(supervisor),
            4.0,
            "replaced Wayland clipboard supervisor exit",
        )

        remaining = accepted_at + ttl + 0.5 - time.monotonic()
        if remaining > 0.0:
            time.sleep(remaining)
        self.assertIsNone(replacement_process.poll())
        self.assertTrue(identity_exists(replacement_identity))
        completed = paste(self.context.environment)
        self.assertTrue(
            completed.returncode == 0 and completed.stdout == replacement,
            "replacement selection did not survive beyond the original TTL; "
            f"returncode={completed.returncode}, output_length={len(completed.stdout)}, "
            f"sha256={safe_digest(completed.stdout)}",
        )


def main() -> int:
    for executable in (DRIVER, WESTON, WL_COPY, WL_PASTE):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise SystemExit(f"required executable is missing: {executable}")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RealWlCopyTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
