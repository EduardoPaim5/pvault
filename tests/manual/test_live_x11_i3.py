#!/usr/bin/env python3
"""Manual, never-CI canary for PVault's clipboard path on a live i3/X11 session."""

from __future__ import annotations

import hashlib
import os
import select
import secrets
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


ACKNOWLEDGEMENT = "--acknowledge-live-clipboard-overwrite"
TTL_SECONDS = 2
TTL_EXIT_MARGIN_SECONDS = 1.0
EXPECTED_OWNER_ARGUMENTS = [
    b"xclip",
    b"-selection",
    b"clipboard",
    b"-in",
    b"-quiet",
]


class CanaryError(RuntimeError):
    """A fail-closed manual-canary error."""


@dataclass
class CapturedProcess:
    label: str
    pid: int
    pidfd: int

    def close(self) -> None:
        if self.pidfd >= 0:
            os.close(self.pidfd)
            self.pidfd = -1


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CanaryError(message)


def executable_from_environment(name: str) -> Path:
    value = os.environ.get(name, "")
    require(bool(value), f"missing required environment variable: {name}")
    path = Path(value)
    require(path.is_absolute(), f"{name} must contain an absolute path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CanaryError(f"cannot resolve {name}") from error
    require(resolved.is_file(), f"{name} is not a regular file")
    require(os.access(resolved, os.X_OK), f"{name} is not executable")
    return resolved


def run_quiet(arguments: list[Path | str], timeout: float = 3.0) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            [os.fspath(item) for item in arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CanaryError(f"command execution failed: {arguments[0]}") from error


def owner_query(owner_tool: Path, selection: str) -> int:
    completed = run_quiet([owner_tool, selection])
    require(completed.returncode == 0, f"cannot query X11 selection {selection}")
    try:
        owner = int(completed.stdout.strip())
    except ValueError as error:
        raise CanaryError(f"malformed X11 selection result for {selection}") from error
    require(owner >= 0, f"invalid X11 selection result for {selection}")
    return owner


def owner_identity_query(owner_tool: Path, selection: str) -> tuple[int, int]:
    completed = run_quiet([owner_tool, selection, "--pid"])
    require(completed.returncode == 0, f"cannot bind X11 selection {selection} to a local PID")
    fields = completed.stdout.split()
    require(len(fields) == 2, f"malformed X11 owner identity for {selection}")
    try:
        owner = int(fields[0])
        owner_pid = int(fields[1])
    except ValueError as error:
        raise CanaryError(f"malformed X11 owner identity for {selection}") from error
    require(owner > 0 and owner_pid > 1, f"invalid X11 owner identity for {selection}")
    return owner, owner_pid


def process_file(pid: int, name: str) -> bytes | None:
    try:
        return (Path("/proc") / str(pid) / name).read_bytes()
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None


def process_ppid(pid: int) -> int | None:
    contents = process_file(pid, "stat")
    if contents is None:
        return None
    command_end = contents.rfind(b")")
    if command_end < 0:
        return None
    fields = contents[command_end + 1 :].split()
    if len(fields) < 2:
        return None
    try:
        return int(fields[1])
    except ValueError:
        return None


def process_uid(pid: int) -> int | None:
    contents = process_file(pid, "status")
    if contents is None:
        return None
    for line in contents.splitlines():
        if line.startswith(b"Uid:"):
            fields = line.split()
            if len(fields) < 2:
                return None
            try:
                return int(fields[1])
            except ValueError:
                return None
    return None


def process_arguments(pid: int) -> list[bytes] | None:
    contents = process_file(pid, "cmdline")
    if contents is None:
        return None
    return contents.rstrip(b"\0").split(b"\0")


def capture_pid(pid: int, label: str) -> CapturedProcess:
    require(pid > 1, f"invalid {label} PID")
    try:
        descriptor = os.pidfd_open(pid, 0)
    except (AttributeError, OSError, ProcessLookupError) as error:
        raise CanaryError(f"cannot capture {label} with pidfd") from error
    return CapturedProcess(label, pid, descriptor)


def pidfd_has_exited(process: CapturedProcess, timeout: float) -> bool:
    poller = select.poll()
    poller.register(process.pidfd, select.POLLIN)
    return bool(poller.poll(max(0, int(timeout * 1000))))


def signal_pidfd(process: CapturedProcess, signal_number: int) -> None:
    try:
        signal.pidfd_send_signal(process.pidfd, signal_number, None, 0)
    except ProcessLookupError:
        return
    except OSError as error:
        if not pidfd_has_exited(process, 0.0):
            raise CanaryError(f"cannot signal captured {process.label} through pidfd") from error


def terminate_captured(process: CapturedProcess | None) -> None:
    if process is None or process.pidfd < 0 or pidfd_has_exited(process, 0.0):
        return
    signal_pidfd(process, signal.SIGTERM)
    if pidfd_has_exited(process, 1.0):
        return
    signal_pidfd(process, signal.SIGKILL)
    if not pidfd_has_exited(process, 2.0):
        raise CanaryError(f"captured {process.label} did not exit after SIGKILL")


def validate_supervisor(process: CapturedProcess) -> None:
    expected_arguments = [b"pvault-clip", b"--worker", b"3", b"4", b"5", b"2"]
    require(process_uid(process.pid) == os.geteuid(), "clipboard supervisor UID mismatch")
    require(process_file(process.pid, "comm") == b"pvault-clip\n",
            "clipboard supervisor process name mismatch")
    require(process_arguments(process.pid) == expected_arguments, "clipboard supervisor argv mismatch")


def find_owner(supervisor: CapturedProcess) -> CapturedProcess:
    deadline = time.monotonic() + 1.5
    while time.monotonic() < deadline:
        try:
            entries = list(Path("/proc").iterdir())
        except OSError as error:
            raise CanaryError("cannot inspect /proc for the clipboard owner") from error
        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            if process_ppid(pid) != supervisor.pid:
                continue
            if process_arguments(pid) != EXPECTED_OWNER_ARGUMENTS:
                continue
            captured: CapturedProcess | None = None
            try:
                captured = capture_pid(pid, "xclip owner")
                require(process_ppid(pid) == supervisor.pid, "xclip owner parent changed")
                require(process_uid(pid) == os.geteuid(), "xclip owner UID mismatch")
                require(process_file(pid, "comm") == b"xclip\n", "xclip owner process name mismatch")
                require(process_arguments(pid) == EXPECTED_OWNER_ARGUMENTS, "xclip owner argv mismatch")
                return captured
            except CanaryError:
                if captured is not None:
                    captured.close()
                raise
        time.sleep(0.01)
    raise CanaryError("could not capture the expected xclip owner before TTL")


def consent(owner_tool: Path) -> None:
    require(owner_query(owner_tool, "CLIPBOARD_MANAGER") == 0,
            "a CLIPBOARD_MANAGER owner is active; disable clipboard history first")
    challenge = secrets.token_hex(4).upper()
    expected = f"SUBSTITUIR CLIPBOARD {challenge}"
    try:
        with (
            open("/dev/tty", "r", encoding="utf-8", errors="strict", buffering=1) as terminal_input,
            open("/dev/tty", "w", encoding="utf-8", errors="strict", buffering=1) as terminal_output,
        ):
            terminal_output.write("\nPVault — canário manual da sessão i3/X11\n")
            terminal_output.write("O clipboard atual será SUBSTITUÍDO e o valor anterior não será lido, salvo ou restaurado.\n")
            terminal_output.write("Somente um canário sintético será usado. Não copie nada durante os próximos segundos.\n")
            terminal_output.write("O TTL encerra a posse do PVault; não prova apagamento ou revogação.\n")
            terminal_output.write(f"Para continuar, digite exatamente: {expected}\n> ")
            terminal_output.flush()
            response = terminal_input.readline(256)
    except (OSError, UnicodeError) as error:
        raise CanaryError("cannot obtain consent through /dev/tty") from error
    require(response.endswith("\n") and response.rstrip("\r\n") == expected,
            "consent phrase did not match; clipboard was not changed")


def preflight(owner_tool: Path, xclip: Path) -> None:
    require(sys.platform.startswith("linux"), "this canary requires Linux")
    require(os.geteuid() != 0, "refusing to run as root")
    require(all(stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr)),
            "stdin, stdout, and stderr must be terminals")
    require(os.environ.get("XDG_SESSION_TYPE") == "x11",
            "XDG_SESSION_TYPE must be exactly x11")
    require(not os.environ.get("WAYLAND_DISPLAY"), "WAYLAND_DISPLAY must be empty")
    require(not os.environ.get("I3SOCK"), "I3SOCK must be absent so i3 is bound through DISPLAY")
    require(bool(os.environ.get("DISPLAY")), "DISPLAY must be set")
    require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
            "Python pidfd APIs are required")
    require(Path("/proc/self/stat").is_file(), "a mounted Linux /proc is required")
    require(xclip.samefile("/usr/bin/xclip"), "canary requires the product xclip path")
    i3 = Path("/usr/bin/i3-msg")
    require(i3.is_file() and os.access(i3, os.X_OK), "required executable is missing: /usr/bin/i3-msg")
    require(run_quiet([i3, "-t", "get_version"]).returncode == 0,
            "cannot reach the active i3 session")
    require(owner_query(owner_tool, "CLIPBOARD_MANAGER") == 0,
            "a CLIPBOARD_MANAGER owner is active; disable clipboard history first")


def parse_supervisor(line: bytes) -> int:
    require(line.startswith(b"SUPERVISOR "), "clipboard driver returned an invalid setup response")
    try:
        return int(line.split(maxsplit=1)[1])
    except (IndexError, ValueError) as error:
        raise CanaryError("clipboard driver returned an invalid supervisor PID") from error


def wait_for_new_selection(owner_tool: Path, previous_owner: int) -> int:
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        current_owner = owner_query(owner_tool, "CLIPBOARD")
        if current_owner != 0 and current_owner != previous_owner:
            return current_owner
        time.sleep(0.01)
    raise CanaryError("PVault did not replace the previous X11 selection owner")


def safe_description(data: bytes) -> str:
    return f"length={len(data)}, sha256={hashlib.sha256(data).hexdigest()}"


def exercise(driver: Path, owner_tool: Path, xclip: Path) -> None:
    helper = driver.parent / "pvault-clip"
    require(helper.is_file() and os.access(helper, os.X_OK), "matching pvault-clip helper is missing")
    canary = bytearray(f"PVAULT-LIVE-I3-X11-{secrets.token_hex(32)}".encode("ascii"))
    process: subprocess.Popen[bytes] | None = None
    driver_capture: CapturedProcess | None = None
    supervisor: CapturedProcess | None = None
    owner: CapturedProcess | None = None
    completed_normally = False
    primary_error: BaseException | None = None
    try:
        process = subprocess.Popen(
            [driver, "send", str(TTL_SECONDS)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        driver_capture = capture_pid(process.pid, "clipboard driver")
        require(process.stdout is not None, "clipboard driver stdout is unavailable")
        readable, _, _ = select.select([process.stdout], [], [], 6.0)
        require(bool(readable), "clipboard driver did not finish preparation")
        first_line = process.stdout.readline()
        supervisor = capture_pid(parse_supervisor(first_line), "clipboard supervisor")
        # PR_SET_DUMPABLE=0 deliberately makes /proc/PID/exe unreadable even to
        # this same-UID harness. Bind identity with pidfd, then validate the
        # reported supervisor and its child through UID, parent, comm and argv.
        validate_supervisor(supervisor)

        # The supervisor has not spawned xclip yet. Repeat the manager check at
        # the last possible point before sending the synthetic payload.
        require(owner_query(owner_tool, "CLIPBOARD_MANAGER") == 0,
                "a clipboard manager appeared; clipboard was not changed")
        previous_selection_owner = owner_query(owner_tool, "CLIPBOARD")

        try:
            stdout, stderr = process.communicate(input=bytes(canary), timeout=7.0)
        except subprocess.TimeoutExpired as error:
            raise CanaryError("clipboard driver timed out") from error
        diagnostics = first_line + stdout + stderr
        require(process.returncode == 0,
                f"clipboard driver failed ({safe_description(diagnostics)})")
        require(bytes(canary) not in diagnostics, "clipboard driver exposed the synthetic canary")
        accepted_at = time.monotonic()

        selection_owner = wait_for_new_selection(owner_tool, previous_selection_owner)
        owner = find_owner(supervisor)
        expected_identity = (selection_owner, owner.pid)
        require(owner_identity_query(owner_tool, "CLIPBOARD") == expected_identity,
                "X11 selection owner is not the captured xclip process")

        # This is the only clipboard-content read in the entire harness, and it
        # occurs only after PVault has acquired the new synthetic selection.
        require(owner_identity_query(owner_tool, "CLIPBOARD") == expected_identity,
                "clipboard identity changed before the synthetic round-trip")
        round_trip = run_quiet([xclip, "-selection", "clipboard", "-out"], timeout=2.0)
        require(round_trip.returncode == 0, "xclip could not read the synthetic selection")
        require(owner_identity_query(owner_tool, "CLIPBOARD") == expected_identity,
                "clipboard identity changed during the synthetic round-trip")
        require(round_trip.stdout == bytes(canary), "synthetic round-trip mismatch")
        for index in range(len(canary)):
            canary[index] = 0

        not_before = accepted_at + 1.5
        require(not pidfd_has_exited(owner, max(0.0, not_before - time.monotonic())),
                "captured xclip owner exited substantially before the TTL")
        require(not pidfd_has_exited(supervisor, 0.0),
                "captured clipboard supervisor exited substantially before the TTL")
        exit_deadline = accepted_at + TTL_SECONDS + TTL_EXIT_MARGIN_SECONDS
        require(pidfd_has_exited(owner, max(0.0, exit_deadline - time.monotonic())),
                "captured xclip owner outlived the bounded TTL")
        require(pidfd_has_exited(supervisor, max(0.0, exit_deadline - time.monotonic())),
                "captured clipboard supervisor outlived the bounded TTL")
        elapsed = time.monotonic() - accepted_at
        require(elapsed <= TTL_SECONDS + TTL_EXIT_MARGIN_SECONDS,
                "clipboard processes exceeded the TTL exit margin")
        completed_normally = True
    except BaseException as error:
        primary_error = error
        raise
    finally:
        for index in range(len(canary)):
            canary[index] = 0
        cleanup_errors: list[CanaryError] = []
        for captured in (owner, supervisor, driver_capture):
            try:
                terminate_captured(captured)
            except CanaryError as error:
                cleanup_errors.append(error)
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                cleanup_errors.append(CanaryError("clipboard driver could not be reaped after pidfd cleanup"))
        for captured in (owner, supervisor, driver_capture):
            if captured is not None:
                captured.close()
        if cleanup_errors:
            cleanup_message = "; ".join(str(error) for error in cleanup_errors)
            if primary_error is not None:
                raise CanaryError(
                    f"{primary_error}; pidfd cleanup also failed: {cleanup_message}"
                ) from primary_error
            raise cleanup_errors[0]
    require(completed_normally, "manual canary did not complete")


def main() -> int:
    if sys.argv != [sys.argv[0], ACKNOWLEDGEMENT]:
        print(f"Usage: {sys.argv[0]} {ACKNOWLEDGEMENT}", file=sys.stderr)
        return 2
    try:
        driver = executable_from_environment("PVAULT_LIVE_X11_DRIVER")
        owner_tool = executable_from_environment("PVAULT_LIVE_X11_OWNER_QUERY")
        xclip = executable_from_environment("PVAULT_LIVE_X11_XCLIP")
        preflight(owner_tool, xclip)
        consent(owner_tool)
        exercise(driver, owner_tool, xclip)
    except CanaryError as error:
        print(f"test-live-x11-i3: {error}", file=sys.stderr)
        return 2

    print("PASS: o canário sintético completou o round-trip e os processos capturados terminaram na janela esperada do TTL.")
    print("Limites: isto não prova confidencialidade contra clientes X11, apagamento, revogação ou ausência de retenção.")
    print("DISPLAY não foi autenticado criptograficamente e o clipboard anterior não foi restaurado.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
