"""#259: an out-of-scope IPv6 address must be refused in any spelling.

Same fail-open class as #247/#224: rules are canonicalized at load (via
ipaddress), but _host_of returned the target host as written, so an alternate
spelling of the deny'd address missed the exact-match deny while the CIDR
allow still admitted it. _host_of must canonicalize an IP literal the same way
rules are.
"""
import unittest

from scope import Scope, _host_of


class IPv6CanonTests(unittest.TestCase):
    def setUp(self):
        self.s = Scope(["2001:db8::/32"], ["2001:db8::1"])

    def test_canonical_spelling_denied(self):
        self.assertFalse(self.s.in_scope_host("http://[2001:db8::1]/"))

    def test_leading_zero_spelling_denied(self):
        self.assertFalse(self.s.in_scope_host("http://[2001:0db8::1]/"))

    def test_expanded_spelling_denied(self):
        self.assertFalse(self.s.in_scope_host("http://[2001:db8:0:0::1]/"))

    def test_uppercase_with_port_denied(self):
        self.assertFalse(self.s.in_scope_host("http://[2001:DB8::0001]:8080/"))

    def test_in_scope_ipv6_still_allowed(self):
        self.assertTrue(self.s.in_scope_host("http://[2001:db8::2]/"))

    def test_ipv4_literal_still_canonical(self):
        # IPv4 already worked via CIDR, but the host form must stay stable.
        self.assertEqual(_host_of("http://127.0.0.1/"), "127.0.0.1")

    def test_host_of_canonicalizes_ipv6(self):
        self.assertEqual(_host_of("http://[2001:0db8::1]/"), "2001:db8::1")

    def test_ipv6_url_and_port_deny_rules_canonicalize(self):
        for rule in (
            "https://[2001:0db8::1]/",
            "https://[2001:0db8::1]:8443/admin",
            "[2001:0db8::1]:8443",
            "https://[2001:DB8:0:0::1]/api",
            "https://[2001:0db8::1%25eth0]:8443/",
        ):
            s = Scope(["2001:db8::/32"], [rule])
            self.assertEqual(s.out_of_scope, ["2001:db8::1"], rule)
            self.assertFalse(s.in_scope_host("https://[2001:db8::1]/"), rule)
            self.assertTrue(s.in_scope_host("https://[2001:db8::2]/"), rule)

    def test_ipv6_url_in_scope_rule_canonicalizes(self):
        s = Scope(["https://[2001:0db8::1]:8443/"])
        self.assertEqual(s.in_scope, ["2001:db8::1"])
        self.assertTrue(s.in_scope_host("https://[2001:db8::1]/"))

    def test_bare_unbracketed_ipv6_targets(self):
        self.assertEqual(_host_of("2001:0db8::1"), "2001:db8::1")
        self.assertEqual(_host_of("2001:db8::1%eth0"), "2001:db8::1")
        self.assertEqual(_host_of("::1"), "::1")
        self.assertFalse(self.s.in_scope_host("2001:0db8::1"))
        self.assertTrue(self.s.in_scope_host("2001:0db8::2"))
        # Ambiguous authority characters must still fail closed.
        self.assertEqual(_host_of(r"2001:0db8::1%eth0\@evil.com"), "")

    def test_plain_ipv6_rule_does_not_emit_false_widened_warning(self):
        for rule in ("2001:db8::1", "[2001:db8::1]", "2001:db8::1%eth0",
                     "example.com # see https://docs.example.com/scope"):
            s = Scope([rule])
            self.assertEqual(s.warnings, [], rule)

    def test_ipv6_rule_with_port_or_path_still_warns(self):
        for rule in ("[2001:db8::1]:8443", "https://[2001:db8::1]/admin"):
            s = Scope([rule])
            self.assertTrue(any("widened to host" in w for w in s.warnings), rule)


if __name__ == "__main__":
    unittest.main()
