"""#265: an out-of-scope asset written `https://host/**` (or `/*/*`) must exclude
the whole host — a deny rule — not be filed as a path-level exclusion the host
check can't enforce. The old check only recognised "", "*", "*/" as whole-host,
so `/**` wrote no rule and the host stayed testable under an in-scope wildcard.
"""
import unittest

from cbh import scope_import as si


class WholeHostPathTests(unittest.TestCase):
    def _rules(self, token, side="out"):
        rules, why = si._parse_token(token, side)
        return rules, why

    def test_double_star_is_whole_host(self):
        rules, why = self._rules("https://auth.api.example.com/**")
        self.assertEqual(rules, [si.exact_rule("auth.api.example.com")],
                         f"/** should deny the whole host, got {rules!r} ({why!r})")

    def test_star_slash_star_is_whole_host(self):
        rules, why = self._rules("https://auth.api.example.com/*/*")
        self.assertEqual(rules, [si.exact_rule("auth.api.example.com")])

    def test_real_path_still_path_limited(self):
        rules, why = self._rules("https://api.example.com/admin")
        self.assertEqual(rules, [])
        self.assertTrue(why.startswith("path:"))

    def test_single_star_unchanged(self):
        rules, _ = self._rules("https://api.example.com/*")
        self.assertEqual(rules, [si.exact_rule("api.example.com")])


if __name__ == "__main__":
    unittest.main()
