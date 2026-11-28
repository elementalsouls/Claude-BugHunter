"""Atomic saves must be durable: the tmp file is closed, complete and fsynced
before os.replace swaps it in. Resume trusts state.json (and memory trusts the
per-host rollup), so a rename of an unflushed tmp could leave an empty file
behind after a crash. Synthetic fixtures only; no network or model calls.
"""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import memory
import state


def _watch(module, test):
    """Patch module.os.replace / fsync to record what the tmp held at rename time."""
    seen = {"fsynced": [], "renamed": []}
    real_replace, real_fsync = module.os.replace, module.os.fsync

    def fsync(fd):
        seen["fsynced"].append(fd)
        real_fsync(fd)

    def replace(src, dst):
        test.assertTrue(seen["fsynced"], "os.replace ran before the tmp was fsynced")
        with open(src, encoding="utf-8") as f:
            seen["renamed"].append(json.load(f))   # complete JSON, not a partial buffer
        real_replace(src, dst)

    return seen, patch.object(module.os, "replace", side_effect=replace), patch.object(module.os, "fsync", side_effect=fsync)


class DurableSaveTests(unittest.TestCase):
    def test_engagement_save_fsyncs_before_replace(self):
        with tempfile.TemporaryDirectory() as base:
            eng = state.Engagement(base, "synthetic")
            eng.add_surface([{"url": "https://example.test/", "vuln_class": "cors"}])
            seen, p_replace, p_fsync = _watch(state, self)
            with p_replace, p_fsync:
                eng.save()
            self.assertEqual(len(seen["renamed"]), 1)
            self.assertEqual(seen["renamed"][0]["surface"][0]["url"], "https://example.test/")
            self.assertFalse(os.path.exists(eng.state_path + ".tmp"))
            self.assertEqual(state.Engagement(base, "synthetic").state["surface"], eng.state["surface"])

    def test_memory_rollup_fsyncs_before_replace(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, {"BUGHUNTER_MEMORY_DIR": d}):
                seen, p_replace, p_fsync = _watch(memory, self)
                with p_replace, p_fsync:
                    memory._write_rollup("example.test", ["nginx"], [], [])
                self.assertEqual([doc["host"] for doc in seen["renamed"]], ["example.test"])
                self.assertEqual(memory.rollup("example.test")["sessions"], 1)


if __name__ == "__main__":
    unittest.main()
