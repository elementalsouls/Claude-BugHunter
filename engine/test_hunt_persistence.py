import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import engine
import state


class HuntPersistenceTests(unittest.TestCase):
    def test_failed_snapshot_leaves_positive_item_retryable(self):
        with tempfile.TemporaryDirectory() as base:
            engagement = state.Engagement(base, "synthetic")
            item = {"url": "https://example.test/", "vuln_class": "cors"}
            engagement.add_surface([item])
            runner = engine.Engine.__new__(engine.Engine)
            runner.eng = engagement
            runner.scope = SimpleNamespace(in_scope_host=lambda _: True)
            runner.max_hunts = runner.parallel = 1
            runner.use_memory = False
            runner._hunt_agent = lambda _: {"vulnerable": True}
            original_replace = state.os.replace

            def fail_candidate_snapshot(source, target):
                if engagement.state["candidates"]:
                    raise OSError("synthetic write failure")
                original_replace(source, target)

            with patch.object(state.os, "replace", side_effect=fail_candidate_snapshot):
                with self.assertRaises(OSError):
                    runner.hunt()
            runner.eng = state.Engagement(base, "synthetic")
            self.assertEqual(runner.eng.worklist(), [item])
            runner.hunt()
            reloaded = state.Engagement(base, "synthetic")
            self.assertEqual(reloaded.worklist(), [])
            self.assertEqual(len(reloaded.state["candidates"]), 1)
