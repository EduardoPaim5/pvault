#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: lsan_probe.py PROBE", file=sys.stderr)
        return 2
    probe = Path(sys.argv[1]).resolve()
    if not probe.is_file() or not os.access(probe, os.X_OK):
        print(f"LSan probe is not executable: {probe}", file=sys.stderr)
        return 2

    environment = os.environ.copy()
    environment.pop("ASAN_OPTIONS", None)
    environment.pop("UBSAN_OPTIONS", None)
    environment["LSAN_OPTIONS"] = (
        "detect_leaks=1:exitcode=23:max_leaks=10:report_objects=1"
    )
    heap_probe = subprocess.run(
        [probe],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
        timeout=20.0,
    )
    marker = b"ERROR: LeakSanitizer: detected memory leaks"
    if heap_probe.returncode != 23 or marker not in heap_probe.stderr:
        diagnostic = heap_probe.stderr.decode("utf-8", "replace")[-4000:]
        print(
            "LSan runtime probe did not detect the intentional leak "
            f"(exit={heap_probe.returncode}):\n{diagnostic}",
            file=sys.stderr,
        )
        return 1

    secure_probe = subprocess.run(
        [probe, "secure"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
        timeout=20.0,
    )
    secure_marker = b"unbalanced sodium_malloc/sodium_free ownership"
    if secure_probe.returncode != 24 or secure_marker not in secure_probe.stderr:
        diagnostic = secure_probe.stderr.decode("utf-8", "replace")[-4000:]
        print(
            "secure-allocation tracker did not detect the intentional leak "
            f"(exit={secure_probe.returncode}):\n{diagnostic}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
