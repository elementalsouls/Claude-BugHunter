"""Regression test for #180 (cbh UnicodeEncodeError on non-UTF-8 consoles).

The cbh CLI prints the glyphs the gate uses — the check/cross marks and the
arrow — throughout its output. On a Windows console the default code page is
cp1252, which cannot encode them, so a bare print() raised UnicodeEncodeError
and the command died mid-run. We reproduce that deterministically on any host by
forcing an ASCII default encoding (PYTHONUTF8=0 + PYTHONCOERCECLOCALE=0 +
LC_ALL=C), which is what Windows hits with cp1252.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ASCII_ENV = dict(os.environ, PYTHONUTF8="0", PYTHONCOERCECLOCALE="0", LC_ALL="C")


class CbhWindowsEncodingTests(unittest.TestCase):
    def test_triage_survives_ascii_locale(self):
        with tempfile.TemporaryDirectory() as tmp:
            finding = Path(tmp) / "finding.md"
            finding.write_text("# clickjacking on logout page\n", encoding="utf-8")
            r = subprocess.run(
                [sys.executable, "cbh/cli.py", "triage", str(finding)],
                cwd=_REPO, env=_ASCII_ENV, capture_output=True, text=True, encoding="utf-8")
            self.assertNotIn("UnicodeEncodeError", r.stderr,
                             f"cbh crashed under ASCII locale:\n{r.stderr}")


if __name__ == "__main__":
    unittest.main()
