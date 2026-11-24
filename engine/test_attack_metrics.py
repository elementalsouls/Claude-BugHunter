"""attack_metrics: leak-proof-by-construction per-operator metrics.

Hard guarantees under test:
  - Stores ONLY generic counters keyed by (stack_sig, vuln_class, technique).
  - A host / url / payload-shaped value is rejected fail-closed — nothing written.
  - Nothing in the store file is ever a host, url, path, or body.
  - rank() returns advisory hit-rate ordering; it computes, it does not fire.
"""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import attack_metrics as AM


class _Store(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        self._env = patch.dict(os.environ, {"BUGHUNTER_METRICS_DIR": self._d.name})
        self._env.start()
        self.addCleanup(self._env.stop)

    def _file(self):
        p = os.path.join(self._d.name, "metrics.json")
        return open(p, encoding="utf-8").read() if os.path.exists(p) else ""


class UpdateRankTests(_Store):
    def test_update_then_rank_by_hit_rate(self):
        AM.update("django|nginx", "idor", attempts=10, successes=4)
        AM.update("django|nginx", "sqli", attempts=10, successes=1)
        AM.update("django|nginx", "xss", attempts=4, successes=3)
        ranked = AM.rank("django|nginx")
        order = [(r["vuln_class"], r["hit_rate"]) for r in ranked]
        # xss .75 > idor .4 > sqli .1
        self.assertEqual([c for c, _ in order], ["xss", "idor", "sqli"])
        self.assertAlmostEqual(order[0][1], 0.75)

    def test_update_accumulates(self):
        AM.update("rails", "idor", attempts=2, successes=1)
        AM.update("rails", "idor", attempts=3, successes=2)
        r = AM.rank("rails")[0]
        self.assertEqual((r["attempts"], r["successes"]), (5, 3))

    def test_rank_unknown_stack_is_empty(self):
        AM.update("django", "idor", attempts=1, successes=1)
        self.assertEqual(AM.rank("laravel"), [])


class LeakProofTests(_Store):
    def test_host_shaped_values_rejected_failclosed(self):
        # a url / host / path must never be accepted — write nothing, return False
        self.assertFalse(AM.update("django", "idor", attempts=1, technique="http://victim.example/x"))
        self.assertFalse(AM.update("victim.example.com", "idor", attempts=1))
        self.assertFalse(AM.update("django", "GET /etc/passwd", attempts=1))
        self.assertFalse(AM.update("10.0.0.5", "idor", attempts=1))
        self.assertFalse(AM.update("django", "idor", attempts=1, technique="id=../../x"))
        self.assertEqual(self._file(), "")   # nothing written at all

    def test_valid_write_contains_no_target_data(self):
        AM.update("django|nginx", "idor", attempts=3, successes=1, technique="sequential-id")
        blob = self._file()
        for bad in ("http", "://", "/", "victim", ".com", "passwd", "id="):
            self.assertNotIn(bad, blob, f"target-shaped token {bad!r} leaked into store")

    def test_update_from_run_aggregates_by_class_no_host(self):
        tested = ["http://a.example/x?id=1|id|idor",
                  "http://a.example/s?q=1|q|xss",
                  "http://a.example/p?id=2|id|idor"]
        confirmed = [{"vuln_class": "idor", "url": "http://a.example/x?id=1"}]
        AM.update_from_run("django", tested, confirmed)
        blob = self._file()
        self.assertNotIn("a.example", blob)
        self.assertNotIn("http", blob)
        ranked = {r["vuln_class"]: r for r in AM.rank("django")}
        self.assertEqual(ranked["idor"]["attempts"], 2)
        self.assertEqual(ranked["idor"]["successes"], 1)
        self.assertEqual(ranked["xss"]["attempts"], 1)
        self.assertEqual(ranked["xss"]["successes"], 0)

    def test_stack_sig_with_single_dot_tech_token_is_allowed(self):
        # legitimate tech fingerprints (asp.net, node.js) must still work
        self.assertTrue(AM.update("asp.net|iis", "deserialization", attempts=1, successes=1))

    def test_multi_label_host_in_stack_sig_rejected(self):
        self.assertFalse(AM.update("api.victim.co.uk", "idor", attempts=1))


if __name__ == "__main__":
    unittest.main()
