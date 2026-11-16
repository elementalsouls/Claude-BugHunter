import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ENGINE_DIR = Path(__file__).resolve().parent


class MockLedgerTests(unittest.TestCase):
    def test_full_mock_run_ignores_engagement_ledger(self):
        with tempfile.TemporaryDirectory() as base:
            ledger = Path(base) / "ledger"
            ledger.mkdir()
            findings = ledger / "findings.jsonl"
            original = (
                '{"host":"localhost","url":"http://localhost:3002/api/account?id=5",'
                '"param":"id","vuln_class":"idor","verdict_reason":"ledger sentinel"}\n'
            )
            findings.write_text(original, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ENGINE_DIR / "engine.py"), "--mock", "--hunt", "--use-memory",
                 "--scope", str(ENGINE_DIR / "engagement.example.json"), "--base", base],
                env={**os.environ, "BUGHUNTER_MEMORY_DIR": str(ledger)},
                capture_output=True, text=True, check=True,
            )
            self.assertNotIn("skipped via ledger", result.stdout)
            self.assertIn("CONFIRMED idor", result.stdout)
            self.assertEqual(findings.read_text(encoding="utf-8"), original)
            self.assertEqual(list(ledger.iterdir()), [findings])
