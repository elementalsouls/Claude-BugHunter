"""Governance: cross-engagement WRITES are gated behind use_memory (symmetry
with the reads). Default (use_memory off) pools NOTHING target-identifying.
The leak-proof metrics store is separate, opt-in via use_metrics, and never
contains a host/url under either mode.
"""
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import engine
import state


def _engine(base, use_memory=False, use_metrics=False):
    e = engine.Engine.__new__(engine.Engine)
    e.eng = state.Engagement(base, "t")
    e.scope = SimpleNamespace(name="t", in_scope=["t.example"], reject_reason=lambda _u: None,
                              in_scope_host=lambda _u: True)
    e.parallel = 1
    e.mock = False
    e.use_memory = use_memory
    e.use_metrics = use_metrics
    e.model = e.max_turns = e.timeout = None
    e.eng.state["targets"] = [{"tech": ["django", "nginx"]}]
    return e


_CAND = {"url": "http://t.example/a?id=5", "param": "id", "vuln_class": "idor",
         "severity": "high", "evidence": "x", "request": "GET /a?id=6"}


class WriteGateTests(unittest.TestCase):
    def setUp(self):
        self._mem = tempfile.TemporaryDirectory(); self.addCleanup(self._mem.cleanup)
        self._met = tempfile.TemporaryDirectory(); self.addCleanup(self._met.cleanup)
        self._base = tempfile.TemporaryDirectory(); self.addCleanup(self._base.cleanup)
        env = patch.dict(os.environ, {"BUGHUNTER_MEMORY_DIR": self._mem.name,
                                      "BUGHUNTER_METRICS_DIR": self._met.name})
        env.start(); self.addCleanup(env.stop)

    def _mem_files(self):
        return sorted(os.listdir(self._mem.name)) if os.path.exists(self._mem.name) else []

    def _run_validate(self, e):
        e.eng.state["candidates"] = [dict(_CAND)]
        with patch.object(e, "_validate_agent",
                          return_value={"real": True, "severity": "high", "reason": "pii"}):
            e.validate()

    def test_default_run_writes_no_ledger(self):
        e = _engine(os.path.join(self._base.name, "a"), use_memory=False)
        self._run_validate(e)
        self.assertEqual(self._mem_files(), [], "default run pooled target data into the ledger")

    def test_use_memory_run_records_host_url_as_before(self):
        e = _engine(os.path.join(self._base.name, "b"), use_memory=True)
        self._run_validate(e)
        findings = os.path.join(self._mem.name, "findings.jsonl")
        self.assertTrue(os.path.exists(findings))
        blob = open(findings, encoding="utf-8").read()
        self.assertIn("t.example", blob)          # host/url recall is the opted-in feature
        self.assertIn("/a?id=5", blob)

    def test_metrics_written_only_when_use_metrics_and_never_host_url(self):
        e = _engine(os.path.join(self._base.name, "c"), use_memory=False, use_metrics=True)
        e.eng.state["tested"] = ["http://t.example/a?id=5|id|idor",
                                 "http://t.example/s?q=1|q|xss"]
        e.eng.state["confirmed"] = [{"vuln_class": "idor", "url": "http://t.example/a?id=5"}]
        e.report()
        metrics = os.path.join(self._met.name, "metrics.json")
        self.assertTrue(os.path.exists(metrics))
        blob = open(metrics, encoding="utf-8").read()
        for bad in ("t.example", "http", "://", "/a?id", "id=5"):
            self.assertNotIn(bad, blob, f"metrics store leaked {bad!r}")
        self.assertIn("idor", blob)
        self.assertEqual(self._mem_files(), [])   # memory store untouched (use_memory off)

    def test_default_report_writes_neither_store(self):
        e = _engine(os.path.join(self._base.name, "d"), use_memory=False, use_metrics=False)
        e.eng.state["tested"] = ["http://t.example/a?id=5|id|idor"]
        e.eng.state["confirmed"] = [{"vuln_class": "idor", "url": "http://t.example/a?id=5"}]
        e.report()
        self.assertEqual(self._mem_files(), [])
        self.assertFalse(os.path.exists(os.path.join(self._met.name, "metrics.json")))


if __name__ == "__main__":
    unittest.main()
