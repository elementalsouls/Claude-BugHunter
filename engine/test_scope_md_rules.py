import os
import tempfile
import unittest

from scope import Scope, _scope_from_md, _section_of

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


# ---- #198: a heading must open a section only when it IS a scope label ----
RECON_MD = """# Engagement — acme

## In scope

- app.example.com

## Recon-seeded live hosts (from cbh manifest — VERIFY in-scope before testing)

- jira.example.com
- legacy.example.com
"""


def _write_tmp(text):
    fd, path = tempfile.mkstemp(suffix=".md")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class ReconSeededHeadingTests(unittest.TestCase):
    def setUp(self):
        self.path = _write_tmp(RECON_MD)

    def tearDown(self):
        os.remove(self.path)

    def test_recon_hosts_are_not_in_scope(self):
        scope = _scope_from_md(self.path)
        self.assertTrue(scope.in_scope_host("https://app.example.com/"))
        self.assertFalse(scope.in_scope_host("https://jira.example.com/"))
        self.assertFalse(scope.in_scope_host("https://legacy.example.com/"))

    def test_recon_hint_warning_names_count(self):
        scope = _scope_from_md(self.path)
        self.assertTrue(any("2 recon-seeded host" in w and "add them to" in w
                            for w in scope.warnings))

    def test_common_in_scope_heading_forms_open_a_section(self):
        for heading in ("## In scope", "## In-Scope Assets", "## Assets in scope",
                        "### In scope (web)"):
            md = "# t\n\n%s\n\n- app.example.com\n" % heading
            path = _write_tmp(md)
            try:
                scope = _scope_from_md(path)
                self.assertTrue(scope.in_scope_host("https://app.example.com/"),
                                "heading did not open in-scope: %r" % heading)
            finally:
                os.remove(path)

    def test_out_of_scope_bold_heading_opens_a_section(self):
        md = "# t\n\n## In scope\n\n- example.com\n\n## **Out of scope:**\n\n- admin.example.com\n"
        path = _write_tmp(md)
        try:
            scope = _scope_from_md(path)
            self.assertFalse(scope.in_scope_host("https://admin.example.com/"))
        finally:
            os.remove(path)

    def test_scaffolder_heading_does_not_open_a_section(self):
        # The heading each scaffolder writes must not be read as a scope label,
        # even though its parenthetical note references the In scope section.
        root = os.path.join(os.path.dirname(__file__), "..")
        for script in ("hunt.sh", "hunt.ps1"):
            with open(os.path.join(root, "scripts", script), encoding="utf-8") as fh:
                text = fh.read()
            line = next(ln for ln in text.splitlines() if "Recon-seeded live hosts" in ln)
            heading = "## Recon-seeded live hosts" + line.split("Recon-seeded live hosts", 1)[1]
            heading = heading.split("')")[0].split('")')[0].rstrip("'\"\\n ")
            self.assertIsNone(_section_of(heading),
                              "%s heading opened a section: %r" % (script, heading))

    def test_mid_sentence_scope_heading_closes_section(self):
        md = "# t\n\n## In scope\n\n- example.com\n\n## Notes about scope rules\n\n- other.test\n"
        path = _write_tmp(md)
        try:
            scope = _scope_from_md(path)
            # the bullet under the mid-sentence heading is NOT added as an in-scope rule
            self.assertFalse(scope.in_scope_host("https://other.test/"))
            self.assertTrue(scope.in_scope_host("https://example.com/"))
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
