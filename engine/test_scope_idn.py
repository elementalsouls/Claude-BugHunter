"""IDN hosts must canonicalize to one form before scope matching (CWE-176, #224).

A Unicode hostname and its punycode (IDNA A-label) spelling are the same host; a
deny rule written in either form must reject both spellings, or an operator can
sneak an excluded host past the gate by swapping encodings. Reported in #224.
"""
import unittest

from scope import Scope, _normalize_rule

# Cyrillic "тест".example.com and its A-label, built from codepoints so this
# file stays pure ASCII (and the leak-guard never trips on a Unicode host).
UNI = "тест.example.com"
PUNY = UNI.encode("idna").decode("ascii")


class IdnCanonicalizationTests(unittest.TestCase):
    def test_punycode_deny_rule_also_rejects_unicode_spelling(self):
        deny = "re:^" + PUNY.replace(".", "\\.") + "$"
        s = Scope(in_scope=["*.example.com"], out_of_scope=[deny])
        self.assertIsNone(s.reject_reason("https://www.example.com/"))
        self.assertIsNotNone(s.reject_reason("https://" + UNI + "/admin"))
        self.assertIsNotNone(s.reject_reason("https://" + PUNY + "/admin"))
        self.assertFalse(s.in_scope_host("https://" + UNI + "/admin"))

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
        bad = "中文..example.com"   # empty label -> not valid IDNA
        s = Scope(in_scope=["*.example.com"], out_of_scope=[])
        self.assertFalse(s.in_scope_host("https://" + bad + "/"))
        self.assertEqual(s.reject_reason("https://" + bad + "/"), "could not parse host")


if __name__ == "__main__":
    unittest.main()
