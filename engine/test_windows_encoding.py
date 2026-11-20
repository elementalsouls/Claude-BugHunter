"""Regression test for issue #190 (engine UnicodeEncodeError on non-UTF-8 locales).

On Windows the default code page is cp1252, so text-mode open() calls without an
explicit encoding crash when the engine writes '->' / em-dash characters to the
log, arsenal map, or report. We can reproduce that deterministically on any host
by forcing an ASCII default encoding (PYTHONUTF8=0 + PYTHONCOERCECLOCALE=0 +
LC_ALL=C), which is what Windows hits with cp1252.
"""
import os
import subprocess
import sys
import tempfile
import unittest

_ENGINE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_ENGINE)
_ASCII_ENV = dict(os.environ, PYTHONUTF8="0", PYTHONCOERCECLOCALE="0", LC_ALL="C")


class WindowsEncodingTests(unittest.TestCase):
    def test_mock_hunt_run_survives_ascii_locale(self):
        """Full --mock --hunt flow must finish without a UnicodeEncodeError."""
        with tempfile.TemporaryDirectory() as base:
            r = subprocess.run(
                [sys.executable, "engine/engine.py",
                 "--scope", "engine/engagement.example.json",
                 "--base", base, "--mock", "--hunt"],
                cwd=_REPO, env=_ASCII_ENV, capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(r.returncode, 0,
                             f"engine crashed under ASCII locale:\n{r.stderr}")
            self.assertNotIn("UnicodeEncodeError", r.stderr)


if __name__ == "__main__":
    unittest.main()
