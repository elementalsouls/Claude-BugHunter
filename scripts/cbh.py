#!/usr/bin/env python3
"""Thin shim — run the cbh CLI from a clone without installing.

Kept for backward compatibility with `scripts/cbh.py <cmd>` and the existing
symlink instructions. The implementation now lives in `cbh/cli.py`, which is also
the pip console-script entry point (`cbh`). See docs/cbh-cli.md.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cbh.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
