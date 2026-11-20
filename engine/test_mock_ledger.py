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
                capture_output=True, text=True, check=True, encoding="utf-8",
            )
            self.assertNotIn("skipped via ledger", result.stdout)
            self.assertIn("CONFIRMED idor", result.stdout)
            self.assertEqual(findings.read_text(encoding="utf-8"), original)
            self.assertEqual(list(ledger.iterdir()), [findings])


    def test_mock_run_does_not_read_or_write_live_engagement_files(self):
        with tempfile.TemporaryDirectory() as base:
            live = Path(base) / "demo-local"
            live.mkdir()
            state = live / "state.json"
            report = live / "report.md"
            state.write_text('{"phase":"recon","marker":"live"}', encoding="utf-8")
            report.write_text("live report", encoding="utf-8")
            command = [sys.executable, str(ENGINE_DIR / "engine.py"), "--mock", "--hunt",
                       "--scope", str(ENGINE_DIR / "engagement.example.json"), "--base", base]
            subprocess.run(command, check=True, capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(state.read_text(encoding="utf-8"), '{"phase":"recon","marker":"live"}')
            self.assertEqual(report.read_text(encoding="utf-8"), "live report")
            self.assertFalse((live / "engine.log").exists())
            mock = Path(base) / ".mock" / "demo-local"
            self.assertIn("CONFIRMED", (mock / "engine.log").read_text(encoding="utf-8"))
            self.assertTrue((mock / "report.md").is_file())
