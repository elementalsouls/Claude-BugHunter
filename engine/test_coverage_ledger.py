#!/usr/bin/env python3
"""
test_coverage_ledger.py — assertions for the coverage ledger and its caveats.

What these prove, rather than assume:

  1. the gate is hard        — one untested pair blocks a clean close
  2. blocked is not covered  — and its note survives into the report
  3. clean close is real     — otherwise the gate is just a blocker
  4. a gap reaches the file  — the deliverable on disk carries the caveat
  5. legacy state upgrades   — pre-ledger engagements still load

Run: python3 engine/test_coverage_ledger.py
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import closure                      # noqa: E402
from state import Engagement        # noqa: E402

SCOPE = os.path.join(HERE, "engagement.example.json")


def _run(base, phases):
    r = subprocess.run([sys.executable, os.path.join(HERE, "engine.py"), "--scope", SCOPE,
                        "--base", base, "--mock", "--phases", phases],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"engine failed:\n{r.stdout}\n{r.stderr}"
    d = os.path.join(base, ".mock", "demo-local")
    return json.load(open(os.path.join(d, "state.json"), encoding="utf-8")), open(os.path.join(d, "report.md"), encoding="utf-8").read()


def test_full_run_records_every_pair():
    with tempfile.TemporaryDirectory() as t:
        st, rep = _run(t, "recon,rank,map,hunt,validate,report")
        expected = closure.expected_coverage(st)
        assert expected, "fixture should discover surface"
        assert closure.coverage_complete(st), f"gaps after a full run: {closure.coverage_gaps(st)}"
        assert "Coverage: **complete**" in rep
        assert "No coverage caveats apply" in rep
    print("  ok  a full run records a verdict for every discovered pair")


def test_gap_reaches_the_report_file():
    """The deliverable on disk must carry the caveat — not just the in-memory verdict."""
    with tempfile.TemporaryDirectory() as t:
        _run(t, "recon,rank,map,hunt,validate,report")
        d = os.path.join(t, ".mock", "demo-local")
        st = json.load(open(os.path.join(d, "state.json"), encoding="utf-8"))
        # mark one genuinely-discovered pair blocked, then re-report
        host, cls = sorted(closure.expected_coverage(st))[0]
        item = next(it for it in st["surface"]
                    if closure._host(it["url"]) == host and it["vuln_class"] == cls)
        st["coverage_by_item"][Engagement._key(item)] = {"verdict": "blocked", "note": "edge 403 — needs allowlisted IP"}
        json.dump(st, open(os.path.join(d, "state.json"), "w", encoding="utf-8"))
        _, rep = _run(t, "report")
        assert "Coverage: **INCOMPLETE**" in rep
        assert "do not read as passing" in rep
        assert "edge 403 — needs allowlisted IP" in rep, "the blocked note must reach the file"
        assert f"`{host}` · {cls}" in rep
    print("  ok  a blocked pair reaches report.md with its note")


def test_hard_gate_and_negative_verdicts():
    s = {"surface": [{"url": "https://a.test/x", "vuln_class": "idor"},
                     {"url": "https://b.test/y", "vuln_class": "ssrf"}],
         "coverage": {"a.test|idor": {"verdict": "clean"}}}
    assert not closure.evaluate(s)["clean"], "one untested pair must block a clean close"
    s["coverage"]["b.test|ssrf"] = {"verdict": "out_of_scope"}
    assert closure.evaluate(s)["clean"], "a recorded verdict closes, even a negative one"
    print("  ok  gate is hard; out_of_scope / not_applicable count as verdicts")


def test_unknown_verdict_rejected():
    with tempfile.TemporaryDirectory() as t:
        e = Engagement(t, "x")
        try:
            e.record_coverage({"url": "https://h.test", "vuln_class": "idor"}, "probably-fine")
        except ValueError:
            print("  ok  an unknown verdict is rejected at write time")
            return
        raise AssertionError("record_coverage accepted an unknown verdict")


def test_legacy_state_upgrades():
    with tempfile.TemporaryDirectory() as t:
        os.makedirs(os.path.join(t, "old"))
        json.dump({"name": "old", "created": "x", "phase": "map", "targets": [], "surface": [],
                   "tested": [], "candidates": [], "confirmed": []},
                  open(os.path.join(t, "old", "state.json"), "w", encoding="utf-8"))
        assert Engagement(t, "old").state["coverage"] == {}
    print("  ok  pre-ledger engagements load without migration")


if __name__ == "__main__":
    print("coverage ledger assertions:")
    closure._demo()
    for fn in (test_full_run_records_every_pair, test_gap_reaches_the_report_file,
               test_hard_gate_and_negative_verdicts, test_unknown_verdict_rejected,
               test_legacy_state_upgrades):
        fn()
    print("all coverage-ledger assertions pass")

class CoverageWorkItemTests(unittest.TestCase):
    def test_one_verdict_cannot_cover_an_untried_endpoint(self):
        first = {"url": "https://a.test/first", "vuln_class": "idor", "param": "a"}
        second = {"url": "https://a.test/second", "vuln_class": "idor", "param": "b"}
        with tempfile.TemporaryDirectory() as base:
            engagement = Engagement(base, "synthetic")
            engagement.add_surface([first, second])
            engagement.mark_tested(first, coverage="clean")
            resumed = Engagement(base, "synthetic")
            self.assertEqual(resumed.worklist(), [second])
            self.assertEqual([g["url"] for g in closure.coverage_gaps(resumed.state)],
                             [second["url"]])
            resumed.record_coverage(second, "blocked", "timeout")
            self.assertIn("parameter `b`", closure.render_caveats(resumed.state))
            resumed.mark_tested(second, coverage="clean")
            self.assertTrue(closure.coverage_complete(resumed.state))

    def test_legacy_pair_does_not_prove_coverage_of_multiple_items(self):
        state = {
            "surface": [
                {"url": "https://a.test/first", "vuln_class": "idor"},
                {"url": "https://a.test/second", "vuln_class": "idor"},
            ],
            "coverage": {"a.test|idor": {"verdict": "clean"}},
        }
        self.assertEqual(len(closure.coverage_gaps(state)), 2)
