"""A single-address IPv6 deny rule must match every spelling of that address.

Rules are normalized with ipaddress (`2001:0db8::1` -> `2001:db8::1`), but the
target host was compared as written, so `http://[2001:0db8::1]/` slipped past an
out-of-scope `2001:db8::1` and fell through to an in-scope IPv6 CIDR.
"""
import unittest

from scope import Scope, _host_of


class IPv6CanonicalHostTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(in_scope=["2001:db8::/32"], out_of_scope=["2001:db8::1"])

    def test_non_canonical_spellings_of_a_denied_ip_stay_out_of_scope(self):
        for url in ("http://[2001:db8::1]/",
                    "http://[2001:0db8::1]/",
                    "http://[2001:db8:0:0::1]:8080/x",
                    "https://[2001:DB8::0001]/"):
            with self.subTest(url=url):
                self.assertFalse(self.scope.in_scope_host(url))
                self.assertIn("out-of-scope", self.scope.reject_reason(url))

    def test_other_addresses_in_the_range_stay_in_scope(self):
        self.assertTrue(self.scope.in_scope_host("http://[2001:0db8::2]/"))
        self.assertEqual(_host_of("http://[2001:0DB8::2]/"), "2001:db8::2")
        self.assertEqual(_host_of("http://10.0.0.1:8080/"), "10.0.0.1")
        self.assertEqual(_host_of("https://App.Example.com./"), "app.example.com")


if __name__ == "__main__":
    unittest.main()
