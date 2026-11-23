import unittest

import scope
from scope import Scope


class RegexRuleCacheTests(unittest.TestCase):
    """`re:` rules are compiled once, not on every check. re's own cache holds ~512
    patterns, so an imported program with thousands of exact-host rules recompiled
    every rule on every check."""

    def test_each_rule_compiles_once_across_many_checks(self):
        rules = [rf"re:^cache-h{i}\.example\.com$" for i in range(600)]
        s = Scope(rules)
        before = scope._regex.cache_info().misses
        for i in range(3):
            self.assertFalse(s.in_scope_host(f"https://other{i}.example.org/"))
        self.assertTrue(s.in_scope_host("https://cache-h599.example.com/"))
        self.assertEqual(scope._regex.cache_info().misses - before, len(rules))

    def test_semantics_are_unchanged(self):
        s = Scope([r"re:^App\.Example\.com$", "re:([bad"])
        self.assertTrue(s.in_scope_host("https://app.example.COM/"))   # still case-insensitive
        self.assertFalse(s.in_scope_host("https://x.app.example.com/"))
        self.assertFalse(s.in_scope_host("https://([bad/"))           # invalid regex matches nothing


if __name__ == "__main__":
    unittest.main()
