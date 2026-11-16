from pathlib import Path
import tempfile
import unittest

import memory


class LedgerRotationLimitTests(unittest.TestCase):
    def test_manual_rotation_respects_the_selected_limit_and_retention(self):
        with tempfile.TemporaryDirectory() as folder:
            live = Path(folder, "findings.jsonl")
            live.write_bytes(b"x" * (1 << 20))
            backup = Path(str(live) + ".1")
            backup.write_bytes(b"previous")
            memory.gc(action="rotate", max_mb=1, keep=1, root=folder)
            self.assertFalse(live.exists())
            self.assertEqual(backup.stat().st_size, 1 << 20)
            self.assertFalse(Path(str(live) + ".2").exists())
