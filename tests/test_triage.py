import argparse
import io
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

from cbh import cli


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

    def test_prose_containing_a_method_name_is_not_request_evidence(self):
        """Q1 wants a real request. "tarGET APPlication" and "inPUT validation" are prose."""
        content = """# Test Finding
- Target application: acme portal (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: novel report
- Proof: theoretical explanation without requests
- Evidence: leaked credential
- Notes: the input validation looks wrong
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "prose_q1.md"
            p.write_text(content, encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                res = cli.cmd_triage(argparse.Namespace(finding=str(p)))
        self.assertEqual(res, 2)
        self.assertIn("✗ Q1", out.getvalue())

    def test_lowercase_request_line_still_satisfies_q1(self):
        """A real request-target after the method counts, in any case."""
        content = """# Test Finding
- Target: http://example.com (in scope)
- Severity: high (impact: critical data leak)
- Attacker: low-priv session
- Not duplicate: novel report
- Proof: get /api/v1/data?user=7
- Evidence: leaked credential
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "lowercase_q1.md"
            p.write_text(content, encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                res = cli.cmd_triage(argparse.Namespace(finding=str(p)))
        self.assertEqual(res, 0)
        self.assertIn("✓ Q1", out.getvalue())

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


if __name__ == "__main__":
    unittest.main()
