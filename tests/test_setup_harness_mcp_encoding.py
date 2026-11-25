"""setup_harness_mcp's write_* helpers must not crash on a non-UTF-8 console
when the module is imported directly (#180 follow-up).

main() reconfigured stdout to UTF-8, but the write_* helpers print the same arrow
glyph and are imported + called directly (unit tests, other tooling), bypassing
that guard → UnicodeEncodeError under cp1252. Reproduced deterministically on any
host by forcing an ASCII default encoding (PYTHONUTF8=0 + LC_ALL=C), which is what
Windows cp1252 and CI under LC_ALL=C hit.
"""
import os
import subprocess
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ASCII_ENV = dict(os.environ, PYTHONUTF8="0", PYTHONCOERCECLOCALE="0", LC_ALL="C")
_CHILD = (
    "from scripts.setup_harness_mcp import write_codex; "
    "write_codex('python3', ['/x/server.py'], {}, dry=True, name='hackerone')"
)


class SetupHarnessEncodingTests(unittest.TestCase):
    def test_write_helper_survives_ascii_console_on_import(self):
        r = subprocess.run([sys.executable, "-c", _CHILD], cwd=_REPO, env=_ASCII_ENV,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0,
                         f"write_codex crashed on an ASCII console:\n{r.stderr}")
        self.assertNotIn("UnicodeEncodeError", r.stderr)


if __name__ == "__main__":
    unittest.main()
