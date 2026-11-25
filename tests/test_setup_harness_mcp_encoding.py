"""Regression test: setup_harness_mcp's write_* helpers must not crash on a
non-UTF-8 console when the module is imported directly.

main() used to reconfigure stdout to UTF-8, but the helpers print the same arrow
glyph. Importing the module and calling write_codex / write_antigravity — which
the unit tests do — bypassed that guard and raised UnicodeEncodeError under
cp1252. We reproduce that deterministically on any host by forcing an ASCII
default encoding (PYTHONUTF8=0 + PYTHONCOERCECLOCALE=0 + LC_ALL=C), which is
what Windows hits with cp1252 and what CI hits under LC_ALL=C.
"""
import os
import subprocess
import sys
import tempfile
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ASCII_ENV = dict(os.environ, PYTHONUTF8="0", PYTHONCOERCECLOCALE="0", LC_ALL="C")
_CHILD = (
    "from scripts.setup_harness_mcp import write_codex; "
    "write_codex('python3', ['/x/server.py'], {}, dry=True, name='hackerone')"
)


class SetupHarnessEncodingTests(unittest.TestCase):
    def test_write_codex_survives_ascii_locale_when_imported(self):
        with tempfile.TemporaryDirectory() as home:
            env = dict(_ASCII_ENV, HOME=home, USERPROFILE=home)
            r = subprocess.run(
                [sys.executable, "-c", _CHILD], cwd=_REPO, env=env,
                capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(r.returncode, 0, f"child crashed:\n{r.stderr}")
        self.assertNotIn("UnicodeEncodeError", r.stderr)
        self.assertIn("Codex", r.stdout)   # the arrow line was reached


if __name__ == "__main__":
    unittest.main()
