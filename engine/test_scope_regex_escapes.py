import unittest

from scope import Scope


class ScopeRegexTests(unittest.TestCase):
    def test_regex_preserves_escape_semantics(self):
        scope = Scope(["example.test"], [r"RE:^api\D\.EXAMPLE\.TEST$"])
        self.assertFalse(scope.in_scope_host("https://apia.example.test/"))
        self.assertTrue(scope.in_scope_host("https://api9.example.test/"))
