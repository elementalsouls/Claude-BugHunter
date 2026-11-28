"""Engagement rejects unsafe or non-str names before touching the disk, so a
scope `name` like "../escaped" cannot write state outside --base."""
import os
import tempfile
import unittest

import state


class EngagementNameTests(unittest.TestCase):
    def test_bad_names_rejected_and_nothing_created(self):
        for bad in ("../escaped", None, "", "  ", ".", "..", "a/b", "a\\b", "C:x", "a\x00b", 5):
            with self.subTest(name=bad), tempfile.TemporaryDirectory() as parent:
                base = os.path.join(parent, "base")
                os.makedirs(base)
                with self.assertRaises(ValueError):
                    state.Engagement(base, bad)
                self.assertEqual(os.listdir(base), [])
                self.assertEqual(os.listdir(parent), ["base"])

    def test_plain_name_creates_evidence_dir(self):
        with tempfile.TemporaryDirectory() as base:
            state.Engagement(base, "demo-local")
            self.assertTrue(os.path.isdir(os.path.join(base, "demo-local", "evidence")))


if __name__ == "__main__":
    unittest.main()
