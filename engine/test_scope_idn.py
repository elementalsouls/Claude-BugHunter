import unittest

from scope import Scope, _normalize_rule

# Cyrillic "test".example.com and its A-label spelling, built from codepoints
# so this file stays pure ASCII. Same pair as issue #224's proof of concept.
UNI = "\u0442\u0435\u0441\u0442.example.com"
PUNY = UNI.encode("idna").decode("ascii")


class IdnCanonicalizationTests(unittest.TestCase):
    def test_punycode_deny_rule_also_rejects_unicode_spelling(self):
        # `cbh scope import` writes an out-of-scope IDN as re:^<punycode>$
        deny = "re:^" + PUNY.replace(".", "\\.") + "$"
        s = Scope(in_scope=["*.example.com"], out_of_scope=[deny])
        self.assertIsNone(s.reject_reason("https://www.example.com/"))
        self.assertIsNotNone(s.reject_reason("https://" + UNI + "/admin"))
        self.assertIsNotNone(s.reject_reason("https://" + PUNY + "/admin"))
        self.assertFalse(s.in_scope_host("https://" + UNI + "/admin"))
        self.assertFalse(s.in_scope_host("https://" + PUNY + "/admin"))

    def test_unicode_rule_and_punycode_rule_normalize_to_one_host(self):
        self.assertEqual(_normalize_rule(UNI), PUNY)
        self.assertEqual(_normalize_rule("*." + UNI), "*." + PUNY)
        s = Scope(in_scope=["*." + UNI], out_of_scope=[])
        self.assertTrue(s.in_scope_host("https://sub." + PUNY + "/admin"))
        self.assertTrue(s.in_scope_host("https://sub." + UNI + "/admin"))

    def test_ascii_hosts_normalize_byte_identical(self):
        for rule in ("example.com", "*.example.com", "re:^api\\.example\\.com$",
                     "10.0.0.0/8", "192.168.1.1"):
            with self.subTest(rule=rule):
                self.assertEqual(_normalize_rule(rule),
                                 _normalize_rule(rule.encode("ascii").decode()))

    def test_unencodable_idn_host_fails_closed(self):
        # Non-ASCII host with an empty label cannot round-trip through IDNA;
        # it must be dropped so the default deny keeps it out of scope.
        bad = "\u4e2d\u6587..example.com"
        s = Scope(in_scope=["*.example.com"], out_of_scope=[])
        self.assertFalse(s.in_scope_host("https://" + bad + "/"))
        self.assertEqual(s.reject_reason("https://" + bad + "/"),
                         "could not parse host")


if __name__ == "__main__":
    unittest.main()
