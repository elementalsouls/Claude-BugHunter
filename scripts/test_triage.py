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

    with tempfile.NamedTemporaryFile("w+", suffix=".md") as f1, \
         tempfile.NamedTemporaryFile("w+", suffix=".md") as f2, \
         tempfile.NamedTemporaryFile("w+", suffix=".md") as f3, \
         tempfile.NamedTemporaryFile("w+", suffix=".md") as f4:

        f1.write(sample_pass_http); f1.flush()
        f2.write(sample_pass_post); f2.flush()
        f3.write(sample_pass_curl); f3.flush()
        f4.write(sample_fail_q1); f4.flush()

        res_http = cmd_triage(argparse.Namespace(finding=f1.name))
        assert res_http == 0, f"Expected 0 (PASS) for HTTP GET, got {res_http}"

        res_post = cmd_triage(argparse.Namespace(finding=f2.name))
        assert res_post == 0, f"Expected 0 (PASS) for HTTP POST, got {res_post}"

        res_curl = cmd_triage(argparse.Namespace(finding=f3.name))
        assert res_curl == 0, f"Expected 0 (PASS) for curl, got {res_curl}"

        res_fail = cmd_triage(argparse.Namespace(finding=f4.name))
        assert res_fail == 2, f"Expected 2 (KILL) for missing request, got {res_fail}"

    print("\n✓ test_triage passed: all assertions verified.")


if __name__ == "__main__":
    test_triage()
