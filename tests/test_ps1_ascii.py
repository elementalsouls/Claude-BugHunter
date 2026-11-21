"""Guard for issues #183/#185: PowerShell scripts must stay pure ASCII.

Windows PowerShell 5.1 decodes BOM-less .ps1 files with the system ANSI code
page, not UTF-8, so any non-ASCII character (em-dash, arrows) corrupts the
script and breaks parsing when hunt.ps1 is dot-sourced from $PROFILE. Keeping
the .ps1 sources ASCII-only sidesteps the whole problem without a BOM.
"""
import glob
import os
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Ps1AsciiTests(unittest.TestCase):
    def test_all_ps1_scripts_are_ascii(self):
        offenders = {}
        for path in glob.glob(os.path.join(_REPO, "scripts", "*.ps1")):
            text = open(path, encoding="utf-8").read()
            bad = sorted({c for c in text if ord(c) > 127})
            if bad:
                offenders[os.path.basename(path)] = [f"U+{ord(c):04X} {c!r}" for c in bad]
        self.assertEqual(offenders, {},
                         f"non-ASCII in .ps1 breaks Windows PowerShell 5.1: {offenders}")


if __name__ == "__main__":
    unittest.main()
