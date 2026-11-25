"""hunt-dispatch's mode=wapt load list is hand-written prose; nothing kept it in
sync, so 10 skills added to the bundle were never loaded in wapt mode (#225).

skill_map.dispatch_wapt_skills parses the fenced block after the 'full hunt-* set'
header, and skill_map.main() now errors when an installed hunt-* skill is missing
from it — the same self-check the skill-lint CI already runs.
"""
import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch

import skill_map

FIXTURE = """# hunt-dispatch

full hunt-* set (all OWASP-relevant):

```
hunt-xss        hunt-sqli       hunt-ssrf
hunt-idor       hunt-csrf-2
```

Later section: see hunt-outside for details.
"""


class DispatchWaptSkillsTests(unittest.TestCase):
    def test_returns_only_names_inside_the_block(self):
        self.assertEqual(
            skill_map.dispatch_wapt_skills(FIXTURE),
            {"hunt-xss", "hunt-sqli", "hunt-ssrf", "hunt-idor", "hunt-csrf-2"},
        )

    def test_none_when_header_absent_or_fence_unclosed(self):
        self.assertIsNone(skill_map.dispatch_wapt_skills("```\nhunt-a\n```\n"))
        unclosed = FIXTURE.split("\n```\n")[0] + "\n```\nhunt-a\n"
        self.assertIsNone(skill_map.dispatch_wapt_skills(unclosed))


class MainDispatchCoverageTests(unittest.TestCase):
    def test_installed_skill_missing_from_list_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("hunt-a", "hunt-b", "hunt-dispatch"):
                os.makedirs(os.path.join(tmp, name))
            with open(os.path.join(tmp, "hunt-dispatch", "SKILL.md"), "w", encoding="utf-8") as f:
                f.write("full hunt-* set:\n\n```\nhunt-a\n```\n")
            out = io.StringIO()
            with patch.object(skill_map, "SKILLS_DIR", tmp), contextlib.redirect_stdout(out):
                rc = skill_map.main([])
        self.assertEqual(rc, 1)
        lines = [l for l in out.getvalue().splitlines() if "missing from hunt-dispatch mode=wapt list" in l]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].endswith("list: hunt-b"))
        self.assertNotIn("hunt-a", lines[0])


if __name__ == "__main__":
    unittest.main()
