import unittest

from cbh import cli


class ReportSectionTests(unittest.TestCase):
    def test_subheadings_and_steps_survive_drafting(self):
        notes = """# Synthetic Finding
## Summary
Example only.
## Steps
Use the synthetic fixture.
### Step 1
Load the test page.
### Step 2
Observe the result.
## Impact
Synthetic impact.
"""
        metadata = cli.parse_finding_metadata(notes)
        self.assertEqual(metadata["impact"], "Synthetic impact.")
        self.assertNotIn("## Impact", metadata["steps"])
        report = cli.render_report(metadata, "hackerone")
        self.assertIn("### Step 1\nLoad the test page.", report)
        self.assertIn("### Step 2\nObserve the result.", report)

    def test_inline_heading_like_text_is_not_a_section(self):
        metadata = cli.parse_finding_metadata("Intro mentions ## Impact\nThis is prose.\n")
        self.assertEqual(metadata["impact"], "")
