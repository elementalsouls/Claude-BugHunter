import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import report_coverage as coverage
import verify_citations as verification


class CitationIdentityTests(unittest.TestCase):
    def test_only_hackerone_citations_claim_hackerone_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "hunt-xss.md").write_text(
                "<https://hackerone.com/reports/42>\n"
                "<https://example.invalid/reports/41>\n"
                "<https://not-hackerone.com/reports/43>\n"
                "A product route like /reports/44 is not a citation.\n",
                encoding="utf-8",
            )
            with patch.object(coverage, "DISCLOSED", tmp), patch.object(verification, "DR", tmp):
                self.assertEqual(coverage.already_cited_ids(), {"42"})
                self.assertEqual(verification.citations(), {"42": {"hunt-xss"}})

    def test_coverage_keeps_other_platform_report_with_same_numeric_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = [
                {"id": 42, "source": "hackerone", "title": "Covered H1 XSS"},
                {"id": 42, "source": "intigriti", "title": "Uncovered Intigriti XSS"},
                {"id": 42, "title": "Covered legacy H1 XSS",
                 "url": "https://hackerone.com/reports/42"},
                {"id": 42, "title": "Unknown source XSS",
                 "url": "https://example.invalid/reports/42"},
            ]
            out = Path(tmp, "gaps.md")
            with patch.object(coverage, "already_cited_ids", return_value={"42"}), patch.object(
                coverage.C, "load_raw", return_value=raw
            ):
                self.assertEqual(coverage.main(["--out", str(out)]), 1)
            gaps = out.read_text(encoding="utf-8")
            self.assertIn("Uncovered Intigriti XSS", gaps)
            self.assertIn("Unknown source XSS", gaps)
            self.assertNotIn("Covered H1 XSS", gaps)
            self.assertNotIn("Covered legacy H1 XSS", gaps)

    def test_platform_caches_do_not_share_numeric_report_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp)
            other = raw / "bugcrowd"
            other.mkdir()
            (other / "42.json").write_text(json.dumps({"title": "Other platform"}))
            with patch.object(verification, "RAW", tmp):
                self.assertIsNone(verification.cached_title("42"))
                h1 = raw / "h1"
                h1.mkdir()
                (h1 / "42.json").write_text(json.dumps({"title": "HackerOne fixture"}))
                self.assertEqual(verification.cached_title("42"), ("HackerOne fixture", "", ""))


if __name__ == "__main__":
    unittest.main()
