#!/usr/bin/env python3
"""Opt-in system tests using a disposable Xvfb server and the real xclip."""

from __future__ import annotations

import hashlib
import os
import secrets
import select
import shutil
import signal
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


DRIVER = Path(os.environ["PVAULT_X11_DRIVER"]).resolve()
OWNER_QUERY = Path(os.environ["PVAULT_X11_OWNER_QUERY"]).resolve()
XVFB = Path(os.environ["PVAULT_XVFB"]).resolve()
XCLIP = Path("/usr/bin/xclip")


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    starttime: bytes


@dataclass(frozen=True)
class X11Context:
    root: Path
    environment: dict[str, str]


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


def owner_query(environment: dict[str, str], selection: str) -> int:
    completed = subprocess.run(
        [OWNER_QUERY, selection],
        cwd=REPOSITORY,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3.0,
        check=False,
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", "replace")[-1000:]
        raise RuntimeError(f"X11 owner query failed: {diagnostic}")
    try:
        return int(completed.stdout.strip())
    except ValueError as error:
        raise RuntimeError("X11 owner query returned malformed output") from error


def xclip_read(environment: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [XCLIP, "-selection", "clipboard", "-out"],
        cwd=REPOSITORY,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3.0,
        check=False,
    )


def find_xclip_child(supervisor: int) -> ProcessIdentity | None:
    expected_arguments = [b"xclip", b"-selection", b"clipboard", b"-in", b"-quiet"]
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if process_ppid(pid) != supervisor:
            continue
        command = process_file(pid, "cmdline")
        if command is None or command.rstrip(b"\0").split(b"\0") != expected_arguments:
            continue
        found = identity(pid)
        if found is not None:
            return found
    return None


def wait_for_clipboard_secret(
    environment: dict[str, str], secret: bytes, timeout: float = 4.0
) -> None:
    deadline = time.monotonic() + timeout
    last_returncode: int | None = None
    last_length = 0
    last_digest = ""
    while time.monotonic() < deadline:
        completed = xclip_read(environment)
        last_returncode = completed.returncode
        last_length = len(completed.stdout)
        last_digest = safe_digest(completed.stdout)
        if completed.returncode == 0 and completed.stdout == secret:
            return
        time.sleep(0.02)
    raise AssertionError(
        "real xclip never returned the synthetic canary; "
        f"returncode={last_returncode}, length={last_length}, sha256={last_digest}"
    )


def wait_for_empty_selection(environment: dict[str, str], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    last_owner = -1
    while time.monotonic() < deadline:
        last_owner = owner_query(environment, "CLIPBOARD")
        if last_owner == 0:
            return
        time.sleep(0.02)
    raise AssertionError(f"CLIPBOARD still has X11 owner {last_owner}")


@contextmanager
def isolated_x11_server() -> Iterator[X11Context]:
    with tempfile.TemporaryDirectory(prefix="pvault-real-x11-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        home = root / "home"
        runtime = root / "runtime"
        home.mkdir(mode=0o700)
        runtime.mkdir(mode=0o700)
        server: subprocess.Popen[bytes] | None = None
        environment: dict[str, str] | None = None

        for number in range(90, 190):
            display = f":{number}"
            if Path(f"/tmp/.X11-unix/X{number}").exists() or Path(f"/tmp/.X{number}-lock").exists():
                continue
            authority = root / f"Xauthority-{number}"
            authority.touch(mode=0o600)
            cookie = secrets.token_hex(16)
            authorization = subprocess.run(
                ["xauth", "-f", authority, "add", display, ".", cookie],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3.0,
                check=False,
            )
            if authorization.returncode != 0:
                continue
            authority.chmod(0o600)
            candidate_environment = {
                "DISPLAY": display,
                "HOME": str(home),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "XAUTHORITY": str(authority),
                "XDG_RUNTIME_DIR": str(runtime),
            }
            for name in ("ASAN_OPTIONS", "LSAN_OPTIONS", "UBSAN_OPTIONS"):
                value = os.environ.get(name)
                if value:
                    candidate_environment[name] = value
            server = subprocess.Popen(
                [
                    XVFB,
                    display,
                    "-screen",
                    "0",
                    "640x480x24",
                    "-nolisten",
                    "tcp",
                    "-auth",
                    authority,
                    "-noreset",
                ],
                cwd=REPOSITORY,
                env=candidate_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and server.poll() is None:
                try:
                    owner_query(candidate_environment, "CLIPBOARD")
                    environment = candidate_environment
                    break
                except (OSError, RuntimeError, subprocess.TimeoutExpired):
                    time.sleep(0.05)
            if environment is not None:
                break
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=2.0)
            server = None

        if server is None or environment is None:
            raise RuntimeError("could not start an authenticated disposable Xvfb server")
        try:
            yield X11Context(root, environment)
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=2.0)


class RealXclipTests(unittest.TestCase):
    context: X11Context

    def setUp(self) -> None:
        self.assertEqual(0, owner_query(self.context.environment, "CLIPBOARD"))
        self.assertEqual(0, owner_query(self.context.environment, "CLIPBOARD_MANAGER"))
        self.supervisors: list[ProcessIdentity] = []

    def tearDown(self) -> None:
        for supervisor in self.supervisors:
            if identity_exists(supervisor):
                signal_identity(supervisor, signal.SIGKILL)
        for supervisor in self.supervisors:
            try:
                wait_until(
                    lambda item=supervisor: not identity_exists(item),
                    4.0,
                    "real clipboard supervisor cleanup",
                )
            except AssertionError:
                pass
        try:
            wait_for_empty_selection(self.context.environment, 4.0)
        except (AssertionError, OSError, RuntimeError, subprocess.TimeoutExpired):
            pass

    def send_secret(self, secret: bytes, ttl: int) -> ProcessIdentity:
        invocation = [DRIVER, "send", str(ttl)]
        invocation_blob = b"\0".join(os.fsencode(value) for value in invocation)
        environment_blob = b"\0".join(
            os.fsencode(key) + b"=" + os.fsencode(value)
            for key, value in self.context.environment.items()
        )
        self.assertNotIn(secret, invocation_blob)
        self.assertNotIn(secret, environment_blob)
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
            self.assertTrue(readable, "real clipboard driver did not finish preparation")
            first_line = process.stdout.readline()
            self.assertTrue(first_line.startswith(b"SUPERVISOR "))
            supervisor_pid = int(first_line.split(maxsplit=1)[1])
            supervisor = identity(supervisor_pid)
            self.assertIsNotNone(supervisor)
            assert supervisor is not None
            self.supervisors.append(supervisor)
            for name in ("cmdline", "environ"):
                contents = process_file(process.pid, name)
                if contents is not None:
                    self.assertNotIn(secret, contents)
            stdout, stderr = process.communicate(input=secret, timeout=8.0)
            diagnostics = first_line + stdout + stderr
            self.assertEqual(
                0,
                process.returncode,
                "real clipboard driver failed; "
                f"output_length={len(diagnostics)}, sha256={safe_digest(diagnostics)}",
            )
            self.assertNotIn(secret, diagnostics)
            return supervisor
        except BaseException:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=2.0)
            raise

    def test_real_xclip_round_trip_and_ttl(self) -> None:
        secret = f"PVAULT-X11-TTL-{secrets.token_hex(16)}".encode("ascii")
        started = time.monotonic()
        supervisor = self.send_secret(secret, 2)
        wait_for_clipboard_secret(self.context.environment, secret)
        owner = find_xclip_child(supervisor.pid)
        self.assertIsNotNone(owner)
        assert owner is not None
        self.assertNotEqual(0, owner_query(self.context.environment, "CLIPBOARD"))
        wait_until(lambda: not identity_exists(owner), 6.0, "real xclip TTL exit")
        wait_until(
            lambda: not identity_exists(supervisor),
            6.0,
            "real clipboard supervisor TTL exit",
        )
        wait_for_empty_selection(self.context.environment)
        self.assertGreaterEqual(time.monotonic() - started, 1.5)

    def test_real_xclip_dies_with_killed_supervisor(self) -> None:
        secret = f"PVAULT-X11-PDEATH-{secrets.token_hex(16)}".encode("ascii")
        supervisor = self.send_secret(secret, 30)
        wait_for_clipboard_secret(self.context.environment, secret)
        owner = find_xclip_child(supervisor.pid)
        self.assertIsNotNone(owner)
        assert owner is not None
        self.assertTrue(signal_identity(supervisor, signal.SIGKILL))
        wait_until(
            lambda: not identity_exists(supervisor),
            4.0,
            "killed real clipboard supervisor",
        )
        wait_until(lambda: not identity_exists(owner), 4.0, "real xclip parent-death exit")
        wait_for_empty_selection(self.context.environment)


def main() -> int:
    for executable in (DRIVER, OWNER_QUERY, XVFB, XCLIP):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise SystemExit(f"required executable is missing: {executable}")
    if shutil.which("xauth") is None:
        raise SystemExit("required executable is missing: xauth")

    with isolated_x11_server() as context:
        RealXclipTests.context = context
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(RealXclipTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
