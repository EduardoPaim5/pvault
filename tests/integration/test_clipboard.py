from __future__ import annotations

import json
import hashlib
import os
import select
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from pty_harness import (
    matching_processes,
    pid_exists,
    process_file,
    process_starttime,
    wait_until,
)


REPOSITORY = Path(__file__).resolve().parents[2]
DRIVER_SOURCE = REPOSITORY / "tests" / "integration" / "clipboard_driver.c"
FAKE_OWNER_SOURCE = REPOSITORY / "tests" / "integration" / "fake_clipboard_owner.c"
PREBUILT_DRIVER = os.environ.get("PVAULT_TEST_CLIPBOARD_DRIVER")
PREBUILT_OWNER = os.environ.get("PVAULT_TEST_CLIPBOARD_OWNER")
PREBUILT_HELPER = os.environ.get("PVAULT_TEST_CLIPBOARD_HELPER")


def poison_clipboard_child_signal_state() -> None:
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)


class ClipboardIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        integration_root = REPOSITORY / "build"
        integration_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        cls._temporary = tempfile.TemporaryDirectory(
            prefix="pvault-clipboard-", dir=integration_root
        )
        cls.root = Path(cls._temporary.name)
        cls.root.chmod(0o700)
        prebuilt = (PREBUILT_DRIVER, PREBUILT_OWNER, PREBUILT_HELPER)
        if all(prebuilt):
            cls.driver = Path(PREBUILT_DRIVER or "").resolve()
            cls.fake_owner = Path(PREBUILT_OWNER or "").resolve()
            cls.helper = Path(PREBUILT_HELPER or "").resolve()
            missing = [
                str(path)
                for path in (cls.driver, cls.fake_owner, cls.helper)
                if not path.is_file() or not os.access(path, os.X_OK)
            ]
            if missing:
                raise RuntimeError(
                    "prebuilt clipboard test executable is missing: " + ", ".join(missing)
                )
            return
        if any(prebuilt):
            raise RuntimeError("all prebuilt clipboard test executable paths are required")

        compiler = shutil.which(os.environ.get("CC", "cc"))
        if compiler is None:
            raise unittest.SkipTest("a C compiler is required for clipboard integration tests")
        cls.build = cls.root / "bin"
        cls.build.mkdir(mode=0o700)
        cls.fake_owner = cls.build / "fake-clipboard-owner"
        cls.driver = cls.build / "clipboard-driver"
        cls.helper = cls.build / "pvault-clip"

        common = [
            compiler,
            "-std=c11",
            "-D_GNU_SOURCE",
            "-D_POSIX_C_SOURCE=200809L",
            "-DPVAULT_EXPERIMENTAL_WAYLAND_CLIPBOARD",
            f'-DPV_XCLIP_PATH="{cls.fake_owner}"',
            f'-DPV_WL_COPY_PATH="{cls.fake_owner}"',
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
            str(REPOSITORY / "include"),
            "-I",
            str(REPOSITORY / "src"),
        ]
        cls._compile(
            common
            + [
                str(FAKE_OWNER_SOURCE),
                "-lsodium",
                "-o",
                str(cls.fake_owner),
            ]
        )
        cls._compile(
            common
            + [
                str(DRIVER_SOURCE),
                str(REPOSITORY / "src" / "clipboard.c"),
                str(REPOSITORY / "src" / "error.c"),
                str(REPOSITORY / "src" / "util.c"),
                "-o",
                str(cls.driver),
            ]
        )
        cls._compile(
            common
            + [
                str(REPOSITORY / "src" / "clip_main.c"),
                str(REPOSITORY / "src" / "clipboard.c"),
                str(REPOSITORY / "src" / "error.c"),
                str(REPOSITORY / "src" / "util.c"),
                "-o",
                str(cls.helper),
            ]
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    @classmethod
    def _compile(cls, command: list[str]) -> None:
        completed = subprocess.run(
            command,
            cwd=REPOSITORY,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30.0,
        )
        if completed.returncode != 0:
            diagnostic = completed.stderr.decode("utf-8", "replace")[-4000:]
            raise RuntimeError(f"clipboard test harness compilation failed:\n{diagnostic}")

    def assert_secret_absent(self, secret: bytes, data: bytes, location: str) -> None:
        if secret in data:
            self.fail(f"secret appeared in {location}")

    def setUp(self) -> None:
        self._baseline_workers = matching_processes(b"pvault-clip", b"--worker")
        self.control_directories: list[Path] = []
        self.owner_starttimes: dict[int, bytes] = {}

    @staticmethod
    def _signal_matching_process(
        pid: int,
        expected_starttime: bytes | None,
        signal_number: int,
        required_argument: bytes | None = None,
    ) -> bool:
        if expected_starttime is None:
            return False
        try:
            pidfd = os.pidfd_open(pid, 0)
        except (AttributeError, OSError, ProcessLookupError):
            return False
        try:
            if process_starttime(pid) != expected_starttime:
                return False
            command = process_file(pid, "cmdline")
            if required_argument is not None:
                if command is None or required_argument not in command.split(b"\0"):
                    return False
            signal.pidfd_send_signal(pidfd, signal_number)
            return True
        except (AttributeError, OSError, ProcessLookupError):
            return False
        finally:
            os.close(pidfd)

    def tearDown(self) -> None:
        new_workers = matching_processes(b"pvault-clip", b"--worker") - self._baseline_workers
        signalled: set[int] = set()
        for pid in new_workers:
            starttime = process_starttime(pid)
            if self._signal_matching_process(
                pid,
                starttime,
                signal.SIGTERM,
                b"--worker",
            ):
                signalled.add(pid)
        for directory in self.control_directories:
            owner_file = directory / "owner.pid"
            if not owner_file.exists():
                continue
            try:
                owner = int(owner_file.read_text(encoding="ascii").strip())
                if self._signal_matching_process(
                    owner,
                    self.owner_starttimes.get(owner),
                    signal.SIGKILL,
                ):
                    signalled.add(owner)
            except (OSError, ValueError):
                pass
        for pid in signalled:
            wait_until(lambda pid=pid: not pid_exists(pid), 4.0, "test process cleanup")

    def _control(self, prefix: str) -> Path:
        directory = Path(tempfile.mkdtemp(prefix=prefix, dir=self.root))
        directory.chmod(0o700)
        self.control_directories.append(directory)
        return directory

    @staticmethod
    def _environment(control: Path, backend: str) -> dict[str, str]:
        environment = {
            "FORBIDDEN_CLIPBOARD_CANARY": "must-not-reach-owner",
            "HOME": str(control),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
        for name in ("ASAN_OPTIONS", "LSAN_OPTIONS", "UBSAN_OPTIONS"):
            value = os.environ.get(name)
            if value:
                environment[name] = value
        if backend == "x11":
            environment["DISPLAY"] = ":pvault-integration"
            environment["XDG_SESSION_TYPE"] = "x11"
        elif backend == "wayland":
            environment["WAYLAND_DISPLAY"] = "wayland-pvault-integration"
            environment["XDG_RUNTIME_DIR"] = str(control)
        else:  # pragma: no cover - internal test misuse
            raise ValueError(backend)
        return environment

    @staticmethod
    def _supervisor_from_output(output: bytes) -> int:
        for line in output.splitlines():
            if line.startswith(b"SUPERVISOR "):
                return int(line.split(maxsplit=1)[1])
        raise AssertionError("driver did not report a supervisor pid")

    def _send_secret(
        self,
        backend: str,
        ttl: int,
        secret: bytes,
        *,
        clear_mode: str | None = None,
        early_exit: bool = False,
        poisoned_signals: bool = False,
    ) -> tuple[Path, int, bytes]:
        control = self._control(f"{backend}-")
        if clear_mode is not None:
            (control / clear_mode).touch(mode=0o600)
        if early_exit:
            (control / "exit-after-read").touch(mode=0o600)
        environment = self._environment(control, backend)
        invocation = [self.driver, "send", str(ttl)]
        invocation_blob = b"\0".join(os.fsencode(item) for item in invocation)
        environment_blob = b"\0".join(
            os.fsencode(key) + b"=" + os.fsencode(value)
            for key, value in environment.items()
        )
        self.assert_secret_absent(secret, invocation_blob, "clipboard argv")
        self.assert_secret_absent(secret, environment_blob, "clipboard environment")

        completed = subprocess.run(
            invocation,
            input=secret,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=REPOSITORY,
            env=environment,
            check=False,
            timeout=10.0,
            preexec_fn=poison_clipboard_child_signal_state if poisoned_signals else None,
        )
        safe_stdout = completed.stdout.replace(secret, b"<redacted>")
        safe_stderr = completed.stderr.replace(secret, b"<redacted>")
        files = sorted(path.name for path in control.iterdir())
        self.assertEqual(
            0,
            completed.returncode,
            f"clipboard driver failed; stdout={safe_stdout!r}; "
            f"stderr={safe_stderr!r}; control_files={files!r}",
        )
        self.assert_secret_absent(secret, completed.stdout, "clipboard stdout")
        self.assert_secret_absent(secret, completed.stderr, "clipboard stderr")
        supervisor = self._supervisor_from_output(completed.stdout)
        wait_until(lambda: (control / "received.ready").exists(), 3.0, "fake owner input")
        result = json.loads((control / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(len(secret), result["length"])
        self.assertEqual(hashlib.sha256(secret).hexdigest(), result["sha256"])
        return control, supervisor, completed.stdout + completed.stderr

    def _send_secret_expect_failure(
        self,
        mode: str,
        result_marker: str,
    ) -> None:
        control = self._control(f"failure-{mode}-")
        (control / mode).touch(mode=0o600)
        secret = (b"PVAULT-FAIL-CLOSED-" + os.urandom(32)) * 16384
        completed = subprocess.run(
            [self.driver, "send", "30"],
            input=secret,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=REPOSITORY,
            env=self._environment(control, "x11"),
            check=False,
            timeout=10.0,
        )
        output = completed.stdout + completed.stderr
        self.assertNotEqual(0, completed.returncode)
        self.assertNotEqual(-signal.SIGPIPE, completed.returncode)
        self.assert_secret_absent(secret, output, "failed clipboard diagnostics")
        supervisor = self._supervisor_from_output(completed.stdout)
        wait_until(lambda: (control / result_marker).exists(), 3.0, result_marker)
        owner = int((control / "owner.pid").read_text(encoding="ascii").strip())
        wait_until(lambda: not pid_exists(owner), 4.0, f"{mode} owner exit")
        wait_until(lambda: not pid_exists(supervisor), 4.0, f"{mode} supervisor exit")
        remaining = matching_processes(b"pvault-clip", b"--worker") - self._baseline_workers
        self.assertEqual(set(), remaining)

    def _assert_owner_metadata_is_secret_free(self, control: Path, secret: bytes, backend: str) -> int:
        owner = int((control / "owner.pid").read_text(encoding="ascii").strip())
        supervisor = int((control / "supervisor.pid").read_text(encoding="ascii").strip())
        result = json.loads((control / "result.json").read_text(encoding="utf-8"))
        self.assertFalse(result["secret_in_argv"])
        self.assertFalse(result["secret_in_cmdline"])
        self.assertFalse(result["secret_in_environment"])
        self.assertFalse(result["forbidden_canary_present"])
        self.assertFalse(result["sigterm_blocked"])
        self.assertTrue(result["sigchld_default"])
        self.assertEqual(backend, result["argument_shape"])
        worker_cmdline = process_file(supervisor, "cmdline")
        if worker_cmdline is not None:
            self.assert_secret_absent(secret, worker_cmdline, "clipboard worker cmdline")
        self.assertTrue(pid_exists(owner))
        self.assertTrue(pid_exists(supervisor))
        starttime = process_starttime(owner)
        self.assertIsNotNone(starttime)
        assert starttime is not None
        self.owner_starttimes[owner] = starttime
        return owner

    def _assert_wayland_clear_completed(
        self,
        control: Path,
        owner: int,
        supervisor: int,
    ) -> None:
        wait_until(lambda: (control / "cleared.ready").exists(), 3.0, "Wayland clear")
        self.assertEqual(
            owner,
            int((control / "owner.pid").read_text(encoding="ascii").strip()),
        )
        self.assertEqual(
            supervisor,
            int((control / "supervisor.pid").read_text(encoding="ascii").strip()),
        )
        clear_result = json.loads(
            (control / "clear-result.json").read_text(encoding="utf-8")
        )
        self.assertEqual("wayland-clear", clear_result["argument_shape"])
        self.assertFalse(clear_result["forbidden_canary_present"])
        self.assertTrue(clear_result["sigchld_default"])
        self.assertFalse(clear_result["sigterm_blocked"])
        self.assertEqual(2, len((control / "invocations.log").read_text().splitlines()))

    def _assert_owner_exit_early_does_not_clear(self, backend: str) -> None:
        secret = b"EARLY-EXIT-CLIPBOARD-SECRET"
        started = time.monotonic()
        control, supervisor, _ = self._send_secret(
            backend,
            20,
            secret,
            early_exit=True,
        )
        owner = int((control / "owner.pid").read_text(encoding="ascii").strip())
        wait_until(lambda: not pid_exists(owner), 3.0, "early owner exit")
        wait_until(lambda: not pid_exists(supervisor), 3.0, "early supervisor exit")
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertTrue((control / "exited-early").exists())
        self.assertEqual(1, len((control / "invocations.log").read_text().splitlines()))
        self.assertFalse((control / "cleared.ready").exists())
        self.assertFalse((control / "clear-result.json").exists())
        self.assertFalse((control / "signal.txt").exists())

    def test_x11_secret_uses_pipe_and_timeout_reaps_owner_and_supervisor(self) -> None:
        secret = b"X11-CLIPBOARD-SECRET-DO-NOT-LOG"
        started = time.monotonic()
        control, supervisor, _ = self._send_secret("x11", 2, secret)
        owner = self._assert_owner_metadata_is_secret_free(control, secret, "x11")
        wait_until(lambda: not pid_exists(owner), 5.0, "X11 owner timeout")
        wait_until(lambda: not pid_exists(supervisor), 5.0, "X11 supervisor exit")
        self.assertGreaterEqual(time.monotonic() - started, 1.5)
        self.assertIn("SIGTERM", (control / "signal.txt").read_text(encoding="ascii"))
        self.assertEqual(1, len((control / "invocations.log").read_text().splitlines()))

    def test_wayland_arguments_environment_and_timeout(self) -> None:
        secret = b"WAYLAND-CLIPBOARD-SECRET-DO-NOT-LOG"
        control, supervisor, output = self._send_secret(
            "wayland",
            1,
            secret,
            poisoned_signals=True,
        )
        self.assertIn(b"CALLER_SIGCHLD ignored", output)
        owner = self._assert_owner_metadata_is_secret_free(control, secret, "wayland")
        wait_until(lambda: not pid_exists(owner), 4.0, "Wayland owner timeout")
        wait_until(lambda: not pid_exists(supervisor), 4.0, "Wayland supervisor exit")
        self._assert_wayland_clear_completed(control, owner, supervisor)

    def test_wayland_binary_secret_uses_octet_stream_without_truncation(self) -> None:
        secret = b"\x00WAYLAND-BINARY-SECRET\xff\x00"
        control, supervisor, _ = self._send_secret("wayland", 1, secret)
        owner = self._assert_owner_metadata_is_secret_free(
            control,
            secret,
            "wayland-binary",
        )
        wait_until(lambda: not pid_exists(owner), 4.0, "Wayland binary owner timeout")
        wait_until(lambda: not pid_exists(supervisor), 4.0, "Wayland binary supervisor exit")
        self._assert_wayland_clear_completed(control, owner, supervisor)

    def test_wayland_invalid_utf8_without_nul_uses_octet_stream(self) -> None:
        secret = b"WAYLAND-INVALID-UTF8-\xff-\xfe"
        control, supervisor, _ = self._send_secret("wayland", 1, secret)
        owner = self._assert_owner_metadata_is_secret_free(
            control,
            secret,
            "wayland-binary",
        )
        wait_until(lambda: not pid_exists(owner), 4.0, "invalid UTF-8 owner timeout")
        wait_until(lambda: not pid_exists(supervisor), 4.0, "invalid UTF-8 supervisor exit")
        self._assert_wayland_clear_completed(control, owner, supervisor)

    def test_wayland_multibyte_utf8_without_nul_remains_text(self) -> None:
        secret = "senha-✓-🔐".encode("utf-8")
        control, supervisor, _ = self._send_secret("wayland", 1, secret)
        owner = self._assert_owner_metadata_is_secret_free(control, secret, "wayland")
        wait_until(lambda: not pid_exists(owner), 4.0, "UTF-8 text owner timeout")
        wait_until(lambda: not pid_exists(supervisor), 4.0, "UTF-8 text supervisor exit")
        self._assert_wayland_clear_completed(control, owner, supervisor)

    def test_wayland_clear_failure_still_reaps_owner_and_supervisor(self) -> None:
        secret = b"WAYLAND-CLEAR-FAILURE-SECRET"
        control, supervisor, _ = self._send_secret(
            "wayland",
            1,
            secret,
            clear_mode="mode-clear-fail",
        )
        owner = self._assert_owner_metadata_is_secret_free(control, secret, "wayland")
        wait_until(lambda: (control / "clear-failed.ready").exists(), 4.0, "failed clear")
        wait_until(lambda: not pid_exists(owner), 4.0, "owner after failed clear")
        wait_until(lambda: not pid_exists(supervisor), 4.0, "supervisor after failed clear")
        self.assertIn("SIGTERM", (control / "signal.txt").read_text(encoding="ascii"))
        self.assertEqual(2, len((control / "invocations.log").read_text().splitlines()))

    def test_wayland_hung_clear_is_bounded_and_reaped(self) -> None:
        secret = b"WAYLAND-HUNG-CLEAR-SECRET"
        control, supervisor, _ = self._send_secret(
            "wayland",
            1,
            secret,
            clear_mode="mode-clear-hang",
        )
        owner = self._assert_owner_metadata_is_secret_free(control, secret, "wayland")
        wait_until(lambda: (control / "clear-started.ready").exists(), 4.0, "hung clear")
        wait_until(lambda: not pid_exists(owner), 5.0, "owner after hung clear")
        wait_until(lambda: not pid_exists(supervisor), 5.0, "supervisor after hung clear")
        self.assertIn(
            "SIGTERM",
            (control / "clear-signal.txt").read_text(encoding="ascii"),
        )
        self.assertIn("SIGTERM", (control / "signal.txt").read_text(encoding="ascii"))
        self.assertEqual(2, len((control / "invocations.log").read_text().splitlines()))

    def test_x11_owner_exit_early_does_not_spawn_a_clear_operation(self) -> None:
        self._assert_owner_exit_early_does_not_clear("x11")

    def test_wayland_owner_exit_early_does_not_spawn_a_clear_operation(self) -> None:
        self._assert_owner_exit_early_does_not_clear("wayland")

    def test_owner_exit_without_reading_fails_closed(self) -> None:
        self._send_secret_expect_failure("mode-exit-without-read", "exited-without-read")

    def test_owner_exit_after_partial_read_fails_closed(self) -> None:
        self._send_secret_expect_failure(
            "mode-exit-after-partial-read",
            "exited-after-partial-read",
        )

    def test_owner_dies_if_supervisor_is_killed_after_receiving_secret(self) -> None:
        secret = b"SUPERVISOR-DEATH-CLIPBOARD-SECRET"
        control, supervisor, _ = self._send_secret("x11", 30, secret)
        owner = self._assert_owner_metadata_is_secret_free(control, secret, "x11")
        supervisor_starttime = process_starttime(supervisor)
        self.assertTrue(
            self._signal_matching_process(
                supervisor,
                supervisor_starttime,
                signal.SIGKILL,
                b"--worker",
            ),
            "refused to signal a supervisor whose identity could not be verified",
        )
        wait_until(lambda: not pid_exists(supervisor), 4.0, "killed supervisor exit")
        wait_until(lambda: not pid_exists(owner), 4.0, "owner parent-death cleanup")
        self.assertIn("SIGTERM", (control / "signal.txt").read_text(encoding="ascii"))

    def test_parent_death_after_inherited_signal_state_is_normalized(self) -> None:
        secret = b"POISONED-SIGNAL-STATE-CLIPBOARD-SECRET"
        control, supervisor, output = self._send_secret(
            "x11",
            30,
            secret,
            poisoned_signals=True,
        )
        self.assertIn(b"CALLER_SIGCHLD ignored", output)
        owner = self._assert_owner_metadata_is_secret_free(control, secret, "x11")
        supervisor_starttime = process_starttime(supervisor)
        self.assertTrue(
            self._signal_matching_process(
                supervisor,
                supervisor_starttime,
                signal.SIGKILL,
                b"--worker",
            ),
            "refused to signal a supervisor whose identity could not be verified",
        )
        wait_until(lambda: not pid_exists(supervisor), 4.0, "poisoned supervisor exit")
        wait_until(lambda: not pid_exists(owner), 4.0, "poisoned owner parent-death cleanup")
        self.assertIn("SIGTERM", (control / "signal.txt").read_text(encoding="ascii"))

    def test_dead_supervisor_returns_error_without_sigpipe_termination(self) -> None:
        secret = b"BROKEN-CONTROL-CHANNEL-SECRET"
        control = self._control("broken-control-")
        process = subprocess.Popen(
            [self.driver, "send", "30"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=REPOSITORY,
            env=self._environment(control, "x11"),
        )
        self.assertIsNotNone(process.stdout)
        assert process.stdout is not None
        readable, _, _ = select.select([process.stdout], [], [], 8.0)
        self.assertTrue(readable, "driver did not finish clipboard preparation")
        first_line = process.stdout.readline()
        supervisor = self._supervisor_from_output(first_line)
        try:
            self.assertTrue(
                self._signal_matching_process(
                    supervisor,
                    process_starttime(supervisor),
                    signal.SIGKILL,
                    b"--worker",
                ),
                "refused to signal a supervisor whose identity could not be verified",
            )
            wait_until(lambda: not pid_exists(supervisor), 4.0, "dead control peer")
            stdout, stderr = process.communicate(input=secret, timeout=5.0)
            output = first_line + stdout + stderr
            self.assertNotEqual(0, process.returncode)
            self.assertNotEqual(-signal.SIGPIPE, process.returncode)
            self.assert_secret_absent(secret, output, "broken-control diagnostics")
            self.assertFalse((control / "owner.pid").exists())
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=2.0)

    def test_signal_while_prepared_leaves_no_worker_or_owner(self) -> None:
        control = self._control("signal-")
        environment = self._environment(control, "x11")
        process = subprocess.Popen(
            [self.driver, "hold", "30"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=REPOSITORY,
            env=environment,
        )
        self.assertIsNotNone(process.stdout)
        assert process.stdout is not None
        readable, _, _ = select.select([process.stdout], [], [], 8.0)
        self.assertTrue(readable, "driver did not finish clipboard preparation")
        line = process.stdout.readline()
        supervisor = self._supervisor_from_output(line)
        self.assertTrue(pid_exists(supervisor))
        process.send_signal(signal.SIGTERM)
        self.assertEqual(-signal.SIGTERM, process.wait(timeout=5.0))
        process.communicate(timeout=1.0)
        wait_until(lambda: not pid_exists(supervisor), 4.0, "worker cleanup after signal")
        self.assertFalse((control / "owner.pid").exists())
        remaining = matching_processes(b"pvault-clip", b"--worker") - self._baseline_workers
        self.assertEqual(set(), remaining)


if __name__ == "__main__":
    unittest.main(verbosity=2)
