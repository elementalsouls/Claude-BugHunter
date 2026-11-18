#!/usr/bin/env python3
"""Self-check for cmd_triage in cbh/cli.py. Stdlib only, no network, no git.

Run: python3 scripts/test_triage.py (exit 0 = pass)

Asserts that:
  1. Findings with standard HTTP requests (e.g. GET/POST ... HTTP/1.1) pass Q1.
  2. Findings with curl commands pass Q1.
  3. Findings without real request evidence fail Q1 and return KILL (exit code 2).
"""
import argparse
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from cbh.cli import cmd_triage  # noqa: E402


def test_triage():
    sample_pass_http = """
# Test Finding
- Target: http://example.com (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: novel report
- Proof: GET /api/v1/data HTTP/1.1
- Evidence: leaked credential
"""

    sample_pass_post = """
# Test Finding
- Target: http://example.com (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: novel report
- Proof: POST /api/v1/data HTTP/1.1
- Evidence: leaked credential
"""

    sample_pass_curl = """
# Test Finding
- Target: http://example.com (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: novel report
- Proof: curl http://example.com/api/v1/data
- Evidence: leaked credential
"""

    sample_fail_q1 = """
# Test Finding
- Target: http://example.com (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: novel report
- Proof: theoretical explanation without requests
- Evidence: leaked credential
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        p1 = os.path.join(tmpdir, "pass_http.md")
        p2 = os.path.join(tmpdir, "pass_post.md")
        p3 = os.path.join(tmpdir, "pass_curl.md")
        p4 = os.path.join(tmpdir, "fail_q1.md")

        with open(p1, "w", encoding="utf-8") as f:
            f.write(sample_pass_http)
        with open(p2, "w", encoding="utf-8") as f:
            f.write(sample_pass_post)
        with open(p3, "w", encoding="utf-8") as f:
            f.write(sample_pass_curl)
        with open(p4, "w", encoding="utf-8") as f:
            f.write(sample_fail_q1)

        res_http = cmd_triage(argparse.Namespace(finding=p1))
        assert res_http == 0, f"Expected 0 (PASS) for HTTP GET, got {res_http}"

        res_post = cmd_triage(argparse.Namespace(finding=p2))
        assert res_post == 0, f"Expected 0 (PASS) for HTTP POST, got {res_post}"

        res_curl = cmd_triage(argparse.Namespace(finding=p3))
        assert res_curl == 0, f"Expected 0 (PASS) for curl, got {res_curl}"

        res_fail = cmd_triage(argparse.Namespace(finding=p4))
        assert res_fail == 2, f"Expected 2 (KILL) for missing request, got {res_fail}"

    print("\n✓ test_triage passed: all assertions verified.")


if __name__ == "__main__":
    test_triage()
