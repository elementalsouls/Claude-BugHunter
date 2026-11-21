import os
import re
import tempfile
import unittest

from scope import Scope, _scope_from_md

SCOPE_MD = """# Engagement — acme

## In scope

- https://app.example.com/login — main app
- api.example.com
- `*.dev.example.com`
- (paste in-scope asset list here)

## Out of scope

- admin.example.com

## Focus areas

- idor
"""

class ScopeFromMarkdownTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".md")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(SCOPE_MD)

    def tearDown(self):
        os.remove(self.path)

    def test_url_bullets_match_the_host_they_point_at(self):
        scope = _scope_from_md(self.path)
        self.assertIn("app.example.com", scope.in_scope)
        self.assertIsNone(scope.reject_reason("https://app.example.com/login"))

    def test_placeholder_bullets_are_not_rules(self):
        scope = _scope_from_md(self.path)
        self.assertFalse([p for p in scope.in_scope if p.startswith("(")])

    def test_explicit_rule_forms_survive_normalization(self):
        scope = _scope_from_md(self.path)
        self.assertIn("api.example.com", scope.in_scope)
        self.assertIn("*.dev.example.com", scope.in_scope)
        self.assertTrue(scope.in_scope_host("https://api.example.com/v1/x"))
        self.assertTrue(scope.in_scope_host("https://a.dev.example.com"))
        self.assertIsNotNone(scope.reject_reason("https://admin.example.com"))

    def test_unlisted_host_is_still_denied(self):
        scope = _scope_from_md(self.path)
        self.assertIsNotNone(scope.reject_reason("https://evil.test"))

    def test_regex_and_cidr_rules_are_untouched(self):
        self.assertEqual(Scope(["re:^lab[0-9]+\\.acme\\.io$"]).reject_reason("https://lab4.acme.io"), None)
        self.assertEqual(Scope(["10.0.0.0/8"]).reject_reason("https://10.1.2.3"), None)


# What `hunt <target> <manifest>` appends to scope.md: hosts found by passive recon,
# which the operator has NOT checked against the program scope. This is the heading
# older scaffolds wrote; existing scope.md files still carry it.
LEGACY_RECON_HEADING = "## Recon-seeded live hosts (from cbh manifest — VERIFY in-scope before testing)"
RECON_SEEDED_MD = """# Scope — acme

## In scope

- app.example.com

## Out of scope

- admin.example.com

{heading}

- app.example.com
- jira.example.com
- legacy.example.com
"""


def _scaffold_heading(script):
    """The recon-seeded heading a hunt scaffolder writes today."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", script)
    with open(path, encoding="utf-8") as fh:
        match = re.search(r"## Recon-seeded[^'\\\n]*", fh.read())
    return match.group(0).strip()


class SectionHeadingTests(unittest.TestCase):
    def _scope(self, text):
        fd, path = tempfile.mkstemp(suffix=".md")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.addCleanup(os.remove, path)
        return _scope_from_md(path)

    def test_recon_seeded_hosts_are_not_in_scope_rules(self):
        scope = self._scope(RECON_SEEDED_MD.format(heading=LEGACY_RECON_HEADING))
        self.assertEqual(scope.in_scope, ["app.example.com"])
        self.assertIsNone(scope.reject_reason("https://app.example.com/"))
        for host in ("jira.example.com", "legacy.example.com"):
            self.assertIsNotNone(scope.reject_reason(f"https://{host}/"), host)

    def test_scaffolders_write_a_heading_that_is_not_a_scope_section(self):
        for script in ("hunt.sh", "hunt.ps1"):
            heading = _scaffold_heading(script)
            self.assertNotRegex(heading.lower(), r"\bin[ -]scope\b", script)
            scope = self._scope(RECON_SEEDED_MD.format(heading=heading))
            self.assertEqual(scope.in_scope, ["app.example.com"], script)

    def test_common_scope_heading_forms_still_open_a_section(self):
        for in_heading, out_heading in (
            ("## In scope", "## Out of scope"),
            ("## In-Scope Assets", "## Out-of-Scope Assets"),
            ("## **In scope:**", "## **Out of scope:**"),
            ("## Assets in scope", "## Assets out of scope"),
            ("### In scope (web)", "### Out of scope (web)"),
        ):
            scope = self._scope(f"{in_heading}\n\n- api.example.com\n\n{out_heading}\n\n- admin.example.com\n")
            self.assertEqual(scope.in_scope, ["api.example.com"], in_heading)
            self.assertEqual(scope.out_of_scope, ["admin.example.com"], out_heading)

    def test_deeper_subheadings_keep_the_current_section(self):
        scope = self._scope("## In scope\n\n### Web\n\n- app.example.com\n\n### APIs\n\n- api.example.com\n")
        self.assertEqual(scope.in_scope, ["app.example.com", "api.example.com"])

    def test_other_headings_that_mention_scope_close_the_section(self):
        for heading in ("## Notes on what is in scope for this program",
                        "## Is staging in scope? (ask the program)",
                        "## OOS clauses worth pre-empting in submissions"):
            scope = self._scope(f"## In scope\n\n- app.example.com\n\n{heading}\n\n- other.example.com\n")
            self.assertEqual(scope.in_scope, ["app.example.com"], heading)

if __name__ == "__main__":
    unittest.main()
