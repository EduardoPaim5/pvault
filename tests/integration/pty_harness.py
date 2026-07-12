"""Small PTY/process helpers for PVault integration tests.

Only Python's standard library is used.  Secrets are written through a PTY or
pipe after process creation; they are never placed in argv or the environment.
"""

from __future__ import annotations

import errno
import os
import pty
import select
import signal
import termios
import time
from pathlib import Path
from typing import Callable, Mapping, Sequence


class PtyProcess:
    """Child process with a real controlling terminal."""

    def __init__(
        self,
        argv: Sequence[str | os.PathLike[str]],
        *,
        cwd: str | os.PathLike[str],
        env: Mapping[str, str],
    ) -> None:
        self.argv = tuple(os.fspath(item) for item in argv)
        self.env = dict(env)
        self.output = bytearray()
        self._secrets: list[bytes] = []
        self._search_position = 0
        self._eof = False
        self.returncode: int | None = None

        pid, master_fd = pty.fork()
        if pid == 0:
            try:
                os.chdir(cwd)
                os.execvpe(self.argv[0], list(self.argv), self.env)
            except BaseException as error:  # pragma: no cover - child-only diagnostic
                message = f"PTY exec failed: {error}\n".encode("utf-8", "replace")
                os.write(2, message)
                os._exit(127)
        self.pid = pid
        self.master_fd = master_fd
        os.set_blocking(self.master_fd, False)

    def _read_once(self, timeout: float) -> bool:
        if self._eof:
            return False
        readable, _, _ = select.select([self.master_fd], [], [], max(0.0, timeout))
        if not readable:
            return False
        try:
            chunk = os.read(self.master_fd, 65536)
        except OSError as error:
            if error.errno == errno.EIO:
                self._eof = True
                return False
            if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return False
            raise
        if not chunk:
            self._eof = True
            return False
        self.output.extend(chunk)
        return True

    def expect(self, needle: bytes, timeout: float = 8.0) -> bytes:
        deadline = time.monotonic() + timeout
        while True:
            position = self.output.find(needle, self._search_position)
            if position >= 0:
                end = position + len(needle)
                self._search_position = end
                return bytes(self.output[:end])
            if self.returncode is not None or time.monotonic() >= deadline:
                raise AssertionError(
                    f"did not observe {needle!r}; output={self.safe_output()!r}, "
                    f"returncode={self.returncode!r}"
                )
            self._read_once(min(0.1, deadline - time.monotonic()))
            self._poll_waitpid()

    def read_for(self, duration: float) -> bytes:
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline and self.returncode is None:
            self._read_once(min(0.05, deadline - time.monotonic()))
            self._poll_waitpid()
        return bytes(self.output)

    def send(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(self.master_fd, view)
            view = view[written:]

    def send_line(self, data: bytes) -> None:
        self.send(data + b"\n")

    def register_secret(self, secret: bytes) -> None:
        if secret and secret not in self._secrets:
            self._secrets.append(bytes(secret))

    def safe_output(self) -> bytes:
        redacted = bytes(self.output)
        for secret in self._secrets:
            redacted = redacted.replace(secret, b"<redacted>")
        return redacted

    def echo_enabled(self) -> bool:
        attributes = termios.tcgetattr(self.master_fd)
        return bool(attributes[3] & termios.ECHO)

    def send_signal(self, signal_number: int) -> None:
        os.kill(self.pid, signal_number)

    def send_signal_group(self, signal_number: int) -> None:
        process_group = os.getpgid(self.pid)
        if process_group == os.getpgrp():
            raise RuntimeError("refusing to signal the test runner's process group")
        os.killpg(process_group, signal_number)

    def _poll_waitpid(self) -> None:
        if self.returncode is not None:
            return
        waited, status = os.waitpid(self.pid, os.WNOHANG)
        if waited == self.pid:
            self.returncode = os.waitstatus_to_exitcode(status)

    def wait(self, timeout: float = 10.0) -> int:
        deadline = time.monotonic() + timeout
        while self.returncode is None:
            self._read_once(0.05)
            self._poll_waitpid()
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"process {self.pid} did not exit; output={self.safe_output()!r}"
                )
        for _ in range(8):
            if not self._read_once(0.01):
                break
        return self.returncode

    def close(self) -> None:
        if self.returncode is None:
            try:
                self.send_signal_group(signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.wait(1.0)
            except TimeoutError:
                try:
                    self.send_signal_group(signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.wait(2.0)
        try:
            os.close(self.master_fd)
        except OSError:
            pass

    def __enter__(self) -> "PtyProcess":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def isolated_environment(root: Path) -> dict[str, str]:
    home = root / "home"
    config = root / "config"
    data = root / "data"
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    config.mkdir(mode=0o700, parents=True, exist_ok=True)
    data.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "TERM": "xterm",
        "XDG_CONFIG_HOME": str(config),
        "XDG_DATA_HOME": str(data),
    }
    for name in ("ASAN_OPTIONS", "LSAN_OPTIONS", "UBSAN_OPTIONS"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def process_file(pid: int, name: str) -> bytes | None:
    try:
        return Path(f"/proc/{pid}/{name}").read_bytes()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None


def process_state(pid: int) -> str | None:
    status = process_file(pid, "status")

    if status is None:
        return None
    for line in status.splitlines():
        if line.startswith(b"State:"):
            fields = line.split()
            return fields[1].decode("ascii", "replace") if len(fields) >= 2 else None
    return None


def process_starttime(pid: int) -> bytes | None:
    stat = process_file(pid, "stat")

    if stat is None:
        return None
    command_end = stat.rfind(b")")
    if command_end < 0:
        return None
    fields = stat[command_end + 1 :].split()
    return fields[19] if len(fields) > 19 else None


def invocation_contains_secret(process: PtyProcess, secret: bytes) -> list[str]:
    violations: list[str] = []
    argv_blob = b"\0".join(os.fsencode(item) for item in process.argv)
    environment_blob = b"\0".join(
        os.fsencode(key) + b"=" + os.fsencode(value)
        for key, value in process.env.items()
    )
    if secret in argv_blob:
        violations.append("constructed argv")
    if secret in environment_blob:
        violations.append("constructed environment")
    cmdline = process_file(process.pid, "cmdline")
    environ = process_file(process.pid, "environ")
    if cmdline is not None and secret in cmdline:
        violations.append("/proc cmdline")
    if environ is not None and secret in environ:
        violations.append("/proc environ")
    return violations


def matching_processes(*needles: bytes) -> set[int]:
    matches: set[int] = set()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if all(needle in cmdline for needle in needles):
            matches.add(int(entry.name))
    return matches


def pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return Path(f"/proc/{pid}").exists()


def wait_until(predicate: Callable[[], bool], timeout: float, description: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {description}")


def initialize_vault(
    pvault: Path,
    vault: Path,
    recovery: Path,
    master_password: bytes,
    *,
    cwd: Path,
    env: Mapping[str, str],
) -> bytes:
    with PtyProcess(
        [pvault, "--vault", vault, "init", "--recovery-out", recovery],
        cwd=cwd,
        env=env,
    ) as process:
        process.register_secret(master_password)
        process.expect(b"New master password: ")
        if process.echo_enabled():
            raise AssertionError("echo was enabled at master-password prompt")
        if invocation_contains_secret(process, master_password):
            raise AssertionError("master password appeared in process invocation")
        process.send_line(master_password)
        process.expect(b"Confirm: ")
        if process.echo_enabled():
            raise AssertionError("echo was enabled at confirmation prompt")
        process.send_line(master_password)
        returncode = process.wait(15.0)
        output = bytes(process.output)
        if returncode != 0:
            raise AssertionError(f"init failed ({returncode}): {process.safe_output()!r}")
        if master_password in output:
            raise AssertionError("master password appeared in terminal output")
        if not process.echo_enabled():
            raise AssertionError("terminal echo was not restored after init")
        return output


def add_record(
    pvault: Path,
    vault: Path,
    master_password: bytes,
    record_password: bytes,
    *,
    title: bytes,
    username: bytes,
    cwd: Path,
    env: Mapping[str, str],
) -> bytes:
    with PtyProcess([pvault, "--vault", vault, "add"], cwd=cwd, env=env) as process:
        process.register_secret(master_password)
        process.register_secret(record_password)
        process.expect(b"Master password: ")
        process.send_line(master_password)
        process.expect(b"Title: ")
        process.send_line(title)
        process.expect(b"Username: ")
        process.send_line(username)
        process.expect(b"Password [g=generate/e=enter] (g): ")
        process.send_line(b"e")
        process.expect(b"Password: ")
        if process.echo_enabled():
            raise AssertionError("echo was enabled at record-password prompt")
        if invocation_contains_secret(process, record_password):
            raise AssertionError("record password appeared in process invocation")
        process.send_line(record_password)
        process.expect(b"URLs (comma-separated): ")
        if record_password in process.output or master_password in process.output:
            raise AssertionError("secret appeared in terminal output after entry")
        if invocation_contains_secret(process, record_password):
            raise AssertionError("record password appeared in argv or environment")
        process.send_line(b"")
        process.expect(b"Notes (single line): ")
        process.send_line(b"")
        process.expect(b"Tags (comma-separated): ")
        process.send_line(b"integration")
        process.expect(b"Custom fields count [0]: ")
        process.send_line(b"")
        returncode = process.wait(15.0)
        output = bytes(process.output)
        if returncode != 0:
            raise AssertionError(f"add failed ({returncode}): {process.safe_output()!r}")
        if record_password in output or master_password in output:
            raise AssertionError("secret appeared in add output")
        if not process.echo_enabled():
            raise AssertionError("terminal echo was not restored after add")
        return output
