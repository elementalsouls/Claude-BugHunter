"""Verify scripts/cbh.py works when invoked through its documented symlink."""
import os
import subprocess
import sys
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "cbh.py")


@unittest.skipIf(os.name == "nt", "symlink install is POSIX-only")
class CbhSymlinkTests(unittest.TestCase):
    def test_help_via_symlink(self):
        with tempfile.TemporaryDirectory() as bindir, tempfile.TemporaryDirectory() as cwd:
            link = os.path.join(bindir, "cbh")
            try:
                os.symlink(SCRIPT, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported")
            env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
            result = subprocess.run([sys.executable, link, "--help"], cwd=cwd, env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
