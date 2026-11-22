import argparse
import io
import re
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

from cbh import cli

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _run_triage(content: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir) / "finding.md"
        p.write_text(content, encoding="utf-8")
        buf = io.StringIO()
        with redirect_stdout(buf):
            res = cli.cmd_triage(argparse.Namespace(finding=str(p)))
    return res, _ANSI_RE.sub("", buf.getvalue())


class TriageGateTests(unittest.TestCase):
    def test_http_request_and_curl_findings_pass(self):
        samples = [
            """# Test Finding
- Target: http://example.com (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: novel report
- Proof: GET /api/v1/data HTTP/1.1
- Evidence: leaked credential
""",
            """# Test Finding
- Target: http://example.com (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: novel report
- Proof: POST /api/v1/data HTTP/1.1
- Evidence: leaked credential
""",
            """# Test Finding
- Target: http://example.com (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: novel report
- Proof: curl http://example.com/api/v1/data
- Evidence: leaked credential
""",
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            for idx, content in enumerate(samples):
                p = Path(tmpdir) / f"pass_{idx}.md"
                p.write_text(content, encoding="utf-8")
                with redirect_stdout(io.StringIO()):
                    res = cli.cmd_triage(argparse.Namespace(finding=str(p)))
                self.assertEqual(res, 0)

    def test_missing_request_evidence_fails_q1(self):
        content = """# Test Finding
- Target: http://example.com (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: novel report
- Proof: theoretical explanation without requests
- Evidence: leaked credential
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "fail_q1.md"
            p.write_text(content, encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                res = cli.cmd_triage(argparse.Namespace(finding=str(p)))
            self.assertEqual(res, 2)

    def test_missing_finding_file_returns_error(self):
        with redirect_stdout(io.StringIO()):
            res = cli.cmd_triage(argparse.Namespace(finding="nonexistent_finding.md"))
        self.assertEqual(res, 2)

    def test_never_submit_signal_kills_finding(self):
        content = """# Test Finding
- Target: http://example.com (in scope)
- Severity: low (impact: informational)
- Attacker: unauthenticated
- Not duplicate: novel report
- Proof: GET / HTTP/1.1
- Evidence: missing security headers
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "never_submit.md"
            p.write_text(content, encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                res = cli.cmd_triage(argparse.Namespace(finding=str(p)))
            self.assertEqual(res, 2)

    def test_downgrade_verdict_when_only_severity_fails(self):
        content = """# Test Finding
- Target: http://example.com (in scope)
- Attacker: standard session
- Not duplicate: novel report
- Proof: GET /api/v1/data HTTP/1.1
- Evidence: leaked credential
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "downgrade.md"
            p.write_text(content, encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                res = cli.cmd_triage(argparse.Namespace(finding=str(p)))
            self.assertEqual(res, 1)

    # ---- #209: Q1 wants a real request-target, not a method word in prose ----
    def test_prose_method_name_is_not_q1_evidence(self):
        content = """# Test Finding
- Target application: acme portal (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: novel report
- Proof: the input validation looks wrong, no request captured
- Evidence: leaked credential
"""
        res, out = _run_triage(content)
        self.assertEqual(res, 2)
        self.assertIn("✗ Q1", out)

    def test_lowercase_request_line_satisfies_q1(self):
        content = """# Test Finding
- Target: http://example.com (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: novel report
- Proof: get /api/v1/data?user=7
- Evidence: leaked credential
"""
        res, out = _run_triage(content)
        self.assertEqual(res, 0)
        self.assertIn("✓ Q1", out)

    def test_markdown_wrapped_request_satisfies_q1(self):
        """A PoC written in markdown — backtick-wrapped or bold method — is a real request."""
        for proof in ("`GET /api/v1/x`", "**GET** /api/v1/x", "GET `/api/v1/x`"):
            content = f"""# Test Finding
- Target: http://example.com (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: novel report
- Proof: {proof}
- Evidence: leaked credential
"""
            res, out = _run_triage(content)
            self.assertEqual(res, 0, f"proof {proof!r} should satisfy Q1")
            self.assertIn("✓ Q1", out)

    # ---- #197: Q7 clickjacking (no hyphen) and Q3 scope-negation ----
    def test_clickjacking_variants_hit_never_submit(self):
        for signal in ("clickjacking", "click-jacking"):
            res, out = _run_triage(f"# {signal} on logout page\n")
            self.assertEqual(res, 2)
            self.assertIn("✗ Q7", out)

    def test_unverified_out_of_scope_fails_q3(self):
        content = """# IDOR on report endpoint

Scope: not verified, possibly out of scope
Asset: unknown, maybe staging
Proof: GET /api/v1/reports/7 HTTP/1.1
Severity: low
Impact: unclear
"""
        res, out = _run_triage(content)
        self.assertIn("✗ Q3", out)

    def test_affirmative_scope_passes_q3(self):
        _, out = _run_triage("- Target: http://example.com (in scope)\n")
        self.assertIn("✓ Q3", out)

    def test_hyphenated_out_of_scope_fails_q3(self):
        """'out-of-scope' (the common hyphenated spelling) must disavow scope too."""
        content = """# IDOR on report endpoint
- Asset: staging.example.com (out-of-scope)
- Proof: GET /api/v1/reports/7 HTTP/1.1
"""
        _, out = _run_triage(content)
        self.assertIn("✗ Q3", out)

    def test_scope_word_in_non_scope_line_does_not_fail_q3(self):
        """A negation word beside 'scope' on a non-scope line must not kill Q3."""
        content = """# Test Finding
- Target: http://example.com (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: novel report
- Proof: curl http://example.com/api/v1/data
- Evidence: leaked credential
- Impact: unclear scope of data exposure
"""
        res, out = _run_triage(content)
        self.assertEqual(res, 0)
        self.assertIn("✓ Q3", out)

    def test_unrelated_negation_words_do_not_fail_q3(self):
        content = """# Test Finding
- Target: http://example.com (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: previously unknown report
- Proof: curl http://example.com/api/v1/data
- Evidence: leaked credential
- Impact: unclear pending triage
"""
        res, out = _run_triage(content)
        self.assertEqual(res, 0)
        self.assertIn("✓ Q3", out)


if __name__ == "__main__":
    unittest.main()
