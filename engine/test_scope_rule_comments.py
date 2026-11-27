"""#270: an inline comment or parenthetical note on a CIDR deny rule must not make
it fail open. `_normalize_rule` returned the whole rule string when the first
token parsed as a CIDR, so `10.9.0.0/16 # note` / `10.9.0.0/16 (corp)` /
`10.0.0.0/8#corp` never parsed as a network and the deny rule admitted the host.
A `#` is never valid in a host or CIDR, so a trailing comment is dropped — except
inside a `re:` rule, which is returned verbatim.
"""
import unittest

from scope import Scope, _normalize_rule


class CidrCommentTests(unittest.TestCase):
    def test_space_comment_on_cidr_deny_still_denies(self):
        s = Scope(["10.0.0.0/8"], ["10.9.0.0/16 # sensitive lab"])
        self.assertFalse(s.in_scope_host("https://10.9.1.1/"))

    def test_nospace_comment_on_cidr_deny_still_denies(self):
        s = Scope(["10.0.0.0/8"], ["10.9.0.0/16#corp"])
        self.assertFalse(s.in_scope_host("https://10.9.1.1/"))

    def test_parenthetical_note_on_cidr_deny_still_denies(self):
        s = Scope(["10.0.0.0/8"], ["10.9.0.0/16 (corp range)"])
        self.assertFalse(s.in_scope_host("https://10.9.1.1/"))

    def test_ipv6_cidr_with_comment(self):
        s = Scope(["2001:db8::/32"], ["2001:db8:9::/48 # lab"])
        self.assertFalse(s.in_scope_host("http://[2001:db8:9::1]/"))

    def test_normalize_returns_bare_cidr(self):
        self.assertEqual(_normalize_rule("10.9.0.0/16 # note"), "10.9.0.0/16")
        self.assertEqual(_normalize_rule("10.9.0.0/16 (corp)"), "10.9.0.0/16")

    def test_re_rule_hash_preserved(self):
        # a `#` inside a re: rule is part of the pattern, not a comment
        self.assertEqual(_normalize_rule("re:^app#1\\.example\\.com$"),
                         "re:^app#1\\.example\\.com$")

    def test_in_scope_cidr_comment_unaffected(self):
        s = Scope(["10.0.0.0/8 # whole corp"])
        self.assertTrue(s.in_scope_host("https://10.1.2.3/"))


if __name__ == "__main__":
    unittest.main()
