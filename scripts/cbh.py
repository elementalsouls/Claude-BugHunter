#!/usr/bin/env python3
"""Thin shim — run the cbh CLI from a clone without installing.

Kept for backward compatibility with `scripts/cbh.py <cmd>` and the existing
symlink instructions. The implementation now lives in `cbh/cli.py`, which is also
the pip console-script entry point (`cbh`). See docs/cbh-cli.md.
"""
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

if __name__ == "__main__" and sys.argv[1:3] == ["scope", "check"]:
    from cbh.scope_check import main as scope_check_main

    raise SystemExit(scope_check_main(sys.argv[3:]))

from cbh.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
