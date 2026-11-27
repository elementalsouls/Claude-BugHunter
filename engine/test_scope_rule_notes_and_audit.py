"""Regression tests for scope rule normalization (trailing notes and `@` in path/query)
and Engine._scope_audit authority extraction.
"""
import unittest

import engine
from scope import Scope, _normalize_rule


class ScopeRuleNormalizationEdgeTests(unittest.TestCase):
    def test_trailing_note_on_host_deny_rule_still_denies(self):
        sc = Scope(["example.com"], ["admin.example.com (internal portal)"])
        self.assertEqual(_normalize_rule("admin.example.com (internal portal)"), "admin.example.com")
        self.assertFalse(sc.in_scope_host("https://admin.example.com/"))

    def test_trailing_note_on_wildcard_and_ip_deny_rules_still_denies(self):
        sc = Scope(
            ["example.com", "10.0.0.0/8"],
            ["*.corp.example.com (staff only)", "10.0.0.5 (bastion)"],
        )
        self.assertEqual(_normalize_rule("*.corp.example.com (staff only)"), "*.corp.example.com")
        self.assertEqual(_normalize_rule("10.0.0.5 (bastion)"), "10.0.0.5")
        self.assertFalse(sc.in_scope_host("https://sso.corp.example.com/"))
        self.assertFalse(sc.in_scope_host("https://10.0.0.5/"))

    def test_at_sign_in_path_or_query_does_not_drop_host(self):
        sc = Scope(
            ["example.com"],
            [
                "https://admin.example.com/@internal",
                "https://staff.example.com?user=alice@evil.org",
                "https://user:pass@legacy.example.com/@team (deprecated)",
            ],
        )
        self.assertEqual(_normalize_rule("https://admin.example.com/@internal"), "admin.example.com")
        self.assertEqual(_normalize_rule("https://staff.example.com?user=alice@evil.org"), "staff.example.com")
        self.assertEqual(_normalize_rule("https://user:pass@legacy.example.com/@team (deprecated)"), "legacy.example.com")
        self.assertFalse(sc.in_scope_host("https://admin.example.com/"))
        self.assertFalse(sc.in_scope_host("https://staff.example.com/"))
        self.assertFalse(sc.in_scope_host("https://legacy.example.com/"))


class ScopeAuditAuthorityTests(unittest.TestCase):
    def _runner(self, scope):
        r = engine.Engine.__new__(engine.Engine)
        r.scope = scope
        return r

    def test_scope_audit_flags_userinfo_backslash_and_ipv6_exfil(self):
        runner = self._runner(Scope(["example.com"]))
        finding = {
            "request": "GET https://example.com@evil.com/leak",
            "evidence": r"exfil to https://example.com\@attacker.org/log and http://[::1]:8080/admin",
            "hosts_contacted": [],
        }
        oos = runner._scope_audit(finding)
        self.assertIn("evil.com", oos)
        self.assertIn("::1", oos)
        self.assertTrue(any("attacker.org" in h for h in oos), oos)

    def test_scope_audit_allows_clean_in_scope_urls_and_catches_nested_query_urls(self):
        runner = self._runner(Scope(["example.com"]))
        finding = {
            "request": "GET https://example.com/redirect?next=https://evil.com/x",
            "evidence": "sent from (https://api.example.com/v1).",
            "hosts_contacted": ["api.example.com"],
        }
        self.assertEqual(runner._scope_audit(finding), ["evil.com"])


if __name__ == "__main__":
    unittest.main()
