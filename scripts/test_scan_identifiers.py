#!/usr/bin/env python3
"""Self-check for scan_identifiers.py. Stdlib only, no network, no git.

Run: python3 scripts/test_scan_identifiers.py   (exit 0 = pass)

Loads the scanner as a module, points its denylist path at a temp dir, and
asserts the three behaviors that matter:
  1. a planted identifier is caught  -> main() returns 1
  2. a clean file is not caught       -> main() returns 0
  3. an empty/missing denylist fails CLOSED -> main() returns 2
"""
import hashlib
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def load_module():
    spec = importlib.util.spec_from_file_location(
        "scan_identifiers", os.path.join(HERE, "scan_identifiers.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    mod = load_module()
    with tempfile.TemporaryDirectory() as tmp:
        scripts = os.path.join(tmp, "scripts")
        os.makedirs(scripts)
        mod.SCRIPTS_DIR = scripts            # redirect denylist lookup
        mod.REPO = tmp
        deny = os.path.join(scripts, ".identifier-denylist.sha256")

        # Denylist with the hash of a fake identifier "acmecorp".
        banned = hashlib.sha256("acmecorp".encode()).hexdigest()
        with open(deny, "w") as fh:
            fh.write("# test denylist\n" + banned + "\n")

        leak = os.path.join(tmp, "leak.md")
        with open(leak, "w") as fh:
            fh.write("The target was AcmeCorp Ltd, an internal engagement.\n")
        clean = os.path.join(tmp, "clean.md")
        with open(clean, "w") as fh:
            fh.write("Generic methodology, no client names here.\n")

        # 1. planted identifier caught
        assert mod.main([leak]) == 1, "expected hit (exit 1) on planted identifier"
        # 2. clean file passes
        assert mod.main([clean]) == 0, "expected clean (exit 0) on benign file"
        # 3. case-insensitive: "ACMECORP" also caught
        loud = os.path.join(tmp, "loud.md")
        with open(loud, "w") as fh:
            fh.write("ACMECORP everywhere\n")
        assert mod.main([loud]) == 1, "expected case-insensitive hit"

        # 4. fail-closed on empty denylist
        with open(deny, "w") as fh:
            fh.write("# comments only, no hashes\n")
        assert mod.main([clean]) == 2, "expected FAIL-CLOSED (exit 2) on empty denylist"
        # 5. fail-closed on missing denylist
        os.remove(deny)
        assert mod.main([clean]) == 2, "expected FAIL-CLOSED (exit 2) on missing denylist"

    print("PASS: scan_identifiers self-check (catch, clean, case-insensitive, fail-closed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
