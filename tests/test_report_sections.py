import argparse
import io
import os
import sys
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

    def test_reporter_line_does_not_leak_os_login(self):
        # #190: the Reporter line must not carry the machine's OS account name.
        env = {"USER": "osloginname", "USERNAME": "win_osloginname"}
        with patch.dict(os.environ, env, clear=True):
            report = cli.render_report({"title": "Test Finding"}, "h1")
        self.assertNotIn("osloginname", report)
        self.assertIn("**Reporter:** (your handle)", report)

    def test_reporter_from_cbh_reporter_env(self):
        with patch.dict(os.environ, {"CBH_REPORTER": "handle_from_env"}, clear=True):
            report = cli.render_report({"title": "T"}, "h1")
        self.assertIn("**Reporter:** handle_from_env", report)

    def test_reporter_from_argument_overrides_env(self):
        with patch.dict(os.environ, {"CBH_REPORTER": "env_handle"}, clear=True):
            report = cli.render_report({"title": "T"}, "h1", reporter="arg_handle")
        self.assertIn("**Reporter:** arg_handle", report)

    def test_steps_to_reproduce_heading_is_parsed(self):
        # #190: heading keyword followed by more words must still match.
        t = "---\nseverity: High\n---\n# T\n\n## Steps to reproduce\n1. curl x\n"
        self.assertEqual(cli.parse_finding_metadata(t)["steps"], "1. curl x")

    def test_proof_of_concept_heading_is_parsed(self):
        t = "# T\n\n## Proof of concept\ndo the thing\n"
        self.assertEqual(cli.parse_finding_metadata(t)["steps"], "do the thing")

    def test_steps_keyword_not_matched_midword(self):
        # '## Stepsister' must not be treated as a steps section.
        md = cli.parse_finding_metadata("# T\n\n## Stepsister\nnope\n")
        self.assertEqual(md["steps"], "")

    def test_platform_hackerone_alias_accepted(self):
        # #190: --platform hackerone should be accepted (alias of h1), not rejected.
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "finding.md"
            f.write_text("# T\n## Summary\nx\n", encoding="utf-8")
            argv = ["cbh", "report", str(f), "--platform", "hackerone"]
            with patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()) as out:
                rc = cli.main()
        self.assertEqual(rc, 0)
        self.assertIn("**Reporter:**", out.getvalue())

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

