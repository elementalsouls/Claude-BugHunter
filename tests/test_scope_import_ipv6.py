"""cbh scope import: bracketed IPv6 literals must not be rejected as placeholders.

Previously `classify()` matched `[...]` as a template placeholder before
`_parse_token()` could parse `[v6]:port`, so bracketed IPv6 out-of-scope URLs
(`https://[2001:db8::1]/`) were sent to manual review with no deny rule
(fail-open), and `_parse_token()`'s `[v6]` branch ignored path limits and
trailing port validation.
"""
import os
import tempfile
import unittest

from cbh import scope_import as si
from scope import _scope_from_md


def _scope_of(text):
    fd, path = tempfile.mkstemp(suffix=".md")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:
        return _scope_from_md(path)
    finally:
        os.remove(path)


class BracketedIPv6ImportTests(unittest.TestCase):
    def test_bracketed_ipv6_urls_become_canonical_rules(self):
        for raw, expected_note in (
            ("[2001:0db8::1]", ""),
            ("https://[2001:0db8::1]/", ""),
            ("https://[2001:0db8::1]/**", ""),
            ("https://[2001:0db8::1]:8443/", "port 8443"),
            ("[2001:DB8:0:0::1]:443", "port 443"),
        ):
            e = si.classify(raw, "URL", "in")
            self.assertEqual((e.status, e.rules, e.reason),
                             ("rule", ["2001:db8::1"], expected_note), raw)

    def test_out_of_scope_bracketed_ipv6_fails_closed_end_to_end(self):
        rec = {
            "handle": "acme",
            "targets": {
                "in_scope": [
                    {"asset_identifier": "2001:db8::/32", "asset_type": "CIDR",
                     "eligible_for_submission": True},
                ],
                "out_of_scope": [
                    {"asset_identifier": "https://[2001:0db8::1]:8443/", "asset_type": "URL",
                     "eligible_for_submission": False},
                ],
            },
        }
        p = si.program_from_record("hackerone", rec)
        s = _scope_of(si.render(p))
        self.assertEqual(s.out_of_scope, ["2001:db8::1"])
        self.assertFalse(s.in_scope_host("https://[2001:db8::1]/"))
        self.assertTrue(s.in_scope_host("https://[2001:db8::2]/"))

    def test_path_limited_bracketed_ipv6_goes_to_review(self):
        e_in = si.classify("https://[2001:0db8::1]:8443/admin", "URL", "in")
        self.assertEqual(e_in.status, "review")
        self.assertEqual(e_in.rules, ["2001:db8::1"])
        self.assertIn("/admin", e_in.reason)

        e_out = si.classify("https://[2001:0db8::1]/blog", "URL", "out")
        self.assertEqual(e_out.status, "review")
        self.assertEqual(e_out.rules, [])
        self.assertIn("/blog", e_out.reason)

    def test_text_import_out_of_scope_bracketed_ipv6_fails_closed(self):
        p = si.program_from_text(
            "In scope\n- 2001:db8::/32\n"
            "Out of scope\n"
            "- https://[2001:0db8::1]:8443/\n"
            "- https://[2001:0db8::3]/ - legacy gateway\n"
            "- Clickjacking:\n"
        )
        s = _scope_of(si.render(p))
        self.assertEqual(s.out_of_scope, ["2001:db8::1"])
        self.assertFalse(s.in_scope_host("https://[2001:db8::1]/"))
        self.assertTrue(s.in_scope_host("https://[2001:db8::2]/"))
        review = [e.raw for e in p.entries if e.status == "review"]
        self.assertIn("https://[2001:0db8::3]/ - legacy gateway", review)
        self.assertIn("Clickjacking:", p.exclusions)

    def test_non_ipv6_brackets_and_malformed_ipv6_remain_review(self):
        for raw in (
            "app[.staging].example.com",
            "https://[tenant].example.com/",
            "https://[2001:db8::1]/[id]",
            "[2001:db8::1]:abc",
            "[2001:db8::1].example.com",
            "[192.0.2.1]:8443",
            "[2001:db8::/32]",
            "https://[2001:db8::1",
        ):
            e = si.classify(raw, "URL", "in")
            self.assertEqual((e.status, e.rules), ("review", []), raw)


if __name__ == "__main__":
    unittest.main()
