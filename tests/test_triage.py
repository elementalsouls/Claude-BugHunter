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
