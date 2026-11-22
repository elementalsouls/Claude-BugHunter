"""A UTF-8 BOM before the YAML frontmatter must not break metadata parsing.

Editors on Windows (and some export tools) prepend a BOM (\\ufeff). The
frontmatter regex anchors on `^---`, which the BOM pushes off the start of the
string, so severity/asset silently fell back to defaults. Reported in #200.
"""
import unittest

from cbh import cli


class ReportUtf8BomTests(unittest.TestCase):
    def test_bom_prefixed_frontmatter_still_parses(self):
        finding = (
            "---\nseverity: Low\nasset: example.test\n---\n"
            "# Sample report\n\n## Summary\nA formatting example.\n"
        )
        for prefix in ("", "﻿"):
            with self.subTest(bom=bool(prefix)):
                md = cli.parse_finding_metadata(prefix + finding)
                self.assertEqual(md["severity"], "Low")
                self.assertEqual(md["asset"], "example.test")
                self.assertEqual(md["title"], "Sample report")


if __name__ == "__main__":
    unittest.main()
