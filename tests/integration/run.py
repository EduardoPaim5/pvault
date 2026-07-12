#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path


DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(DIRECTORY))


def main() -> int:
    suite = unittest.defaultTestLoader.discover(
        str(DIRECTORY),
        pattern="test_*.py",
        top_level_dir=str(DIRECTORY),
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
