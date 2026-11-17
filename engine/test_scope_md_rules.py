import os
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

if __name__ == "__main__":
    unittest.main()
