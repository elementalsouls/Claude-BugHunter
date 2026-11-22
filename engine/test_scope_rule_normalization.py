#!/usr/bin/env python3
"""Tests for scope rule normalization, IPv6 CIDR, soft-fail regex, warning surfacing.

Covers issues #182 (out-of-scope rules fail open) and the softer-defaults design.
"""
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from scope import Scope  # noqa: E402


class RuleNormalizationTests(unittest.TestCase):
    # ---- #182: deny rules in normal program-page syntax must actually deny ----
    def test_port_rule_denies(self):
        s = Scope(in_scope=["example.com"], out_of_scope=["admin.example.com:8443"])
        self.assertFalse(s.in_scope_host("https://admin.example.com/"))

    def test_scheme_rule_denies(self):
        s = Scope(in_scope=["example.com"], out_of_scope=["https://admin.example.com"])
        self.assertFalse(s.in_scope_host("https://admin.example.com/"))

    def test_path_rule_denies_whole_host(self):
        s = Scope(in_scope=["example.com"], out_of_scope=["admin.example.com/panel"])
        self.assertFalse(s.in_scope_host("https://admin.example.com/"))

    def test_trailing_dot_rule_denies(self):
        s = Scope(in_scope=["example.com"], out_of_scope=["admin.example.com."])
        self.assertFalse(s.in_scope_host("https://admin.example.com/"))

    def test_trailing_comma_rule_denies(self):
        s = Scope(in_scope=["example.com"], out_of_scope=["admin.example.com,"])
        self.assertFalse(s.in_scope_host("https://admin.example.com/"))

    def test_wildcard_scheme_rule_denies(self):
        s = Scope(in_scope=["example.com"], out_of_scope=["https://*.corp.example.com"])
        self.assertFalse(s.in_scope_host("https://x.corp.example.com/"))

    # ---- in-scope normalization (Review Focus: applies to in-scope too) ----
    def test_in_scope_url_rule_still_matches_host(self):
        s = Scope(in_scope=["https://app.example.com/login"])
        self.assertTrue(s.in_scope_host("http://app.example.com/x"))

    def test_port_or_path_rule_records_widen_warning(self):
        s = Scope(in_scope=["example.com"], out_of_scope=["admin.example.com/panel"])
        self.assertTrue(any("widened to host" in w for w in s.warnings))

    # ---- Task 2: IPv6-aware CIDR ----
    def test_ipv6_cidr_matches_ipv6_host(self):
        s = Scope(in_scope=["2001:db8::/32"])
        self.assertTrue(s.in_scope_host("https://[2001:db8::1]/"))

    def test_ipv4_cidr_rule_vs_ipv6_host_no_match_no_raise(self):
        s = Scope(in_scope=["10.0.0.0/8"])
        self.assertFalse(s.in_scope_host("https://[2001:db8::1]/"))

    def test_ipv6_cidr_rule_vs_ipv4_host_no_match(self):
        s = Scope(in_scope=["2001:db8::/32"])
        self.assertFalse(s.in_scope_host("https://10.1.2.3/"))

    # ---- Task 3: soft-fail an invalid out-of-scope regex ----
    def test_bad_out_of_scope_regex_warns_and_continues(self):
        s = Scope(in_scope=["example.com"], out_of_scope=["re:(unclosed"])
        self.assertTrue(any("invalid" in w and "re:(unclosed" in w for w in s.warnings))
        self.assertTrue(s.in_scope_host("https://example.com/"))  # run continues

    def test_valid_out_of_scope_regex_still_denies(self):
        s = Scope(in_scope=["example.com"], out_of_scope=[r"re:^admin\.example\.com$"])
        self.assertFalse(s.in_scope_host("https://admin.example.com/"))

    def test_bad_regex_rule_is_replaced_not_kept_verbatim(self):
        s = Scope(in_scope=["example.com"], out_of_scope=["re:(unclosed"])
        self.assertFalse(any(r.startswith("re:") for r in s.out_of_scope))


class WarningSurfacingTests(unittest.TestCase):
    # ---- Task 5: warnings go to stderr, stdout stays clean, exit unchanged ----
    def test_cli_prints_warning_to_stderr(self):
        scope_py = os.path.join(os.path.dirname(__file__), "scope.py")
        r = subprocess.run(
            [sys.executable, scope_py, "https://example.com/",
             "--in-scope", "example.com", "--out-of-scope", "re:(bad"],
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)          # host in scope, exit 0
        self.assertIn("invalid", r.stderr)         # warning on stderr
        self.assertNotIn("invalid", r.stdout)      # stdout stays clean
        self.assertIn("IN-SCOPE", r.stdout)


if __name__ == "__main__":
    unittest.main()
