import argparse
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

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

    def test_headings_inside_fences_remain_evidence(self):
        notes = """~~~markdown
# Fake title
## Summary
Fake summary.
~~~

# Actual finding
## Summary
Actual summary.
## Steps
````markdown
```markdown
## Impact
Fake impact.
```
````
After the sample.
## Impact
Actual impact.
"""
        metadata = cli.parse_finding_metadata(notes)
        self.assertEqual(metadata["title"], "Actual finding")
        self.assertEqual(metadata["summary"], "Actual summary.")
        self.assertEqual(metadata["impact"], "Actual impact.")
        self.assertIn("## Impact\nFake impact.", metadata["steps"])
        self.assertTrue(metadata["steps"].endswith("After the sample."))

    def test_render_report_uses_username_when_user_unset(self):
        env = {"USERNAME": "win_researcher"}
        with patch.dict(os.environ, env, clear=True):
            report = cli.render_report({"title": "Test Finding"}, "hackerone")
            self.assertIn("**Reporter:** win_researcher", report)

    def test_cmd_report_creates_parent_dirs_and_writes_utf8(self):
        finding_content = """# Unicode Finding — café & 特殊文字
## Summary
Finding summary with special bullet • and em-dash —.
## Steps
curl -H "X-Test: café" https://example.com/api
## Impact
High impact.
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cwd = Path(tmpdir).resolve()
            finding_file = cwd / "finding.md"
            finding_file.write_text(finding_content, encoding="utf-8")
            out_file = cwd / "reports" / "draft.md"
            args = argparse.Namespace(
                finding=str(finding_file),
                platform="hackerone",
                out=str(out_file),
            )
            with patch.object(Path, "cwd", return_value=cwd), redirect_stdout(io.StringIO()):
                ret = cli.cmd_report(args)
            self.assertEqual(ret, 0)
            self.assertTrue(out_file.exists())
            written_text = out_file.read_text(encoding="utf-8")
            self.assertIn("Unicode Finding — café & 特殊文字", written_text)
            self.assertIn("Finding summary with special bullet • and em-dash —.", written_text)

