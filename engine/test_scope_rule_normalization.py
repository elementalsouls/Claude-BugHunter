import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from scope import Scope, _main, _scope_from_md


class OutOfScopeRulesDoNotFailOpenTests(unittest.TestCase):
    """Every way a program page writes an out-of-scope asset must still deny it.

    Before normalization each of these deny rules matched nothing, so the host
    fell through to the broader in-scope rule and was treated as testable.
    """

    DENY_FORMS = {
        "port": "admin.example.com:8443",
        "scheme": "https://admin.example.com",
        "scheme and path": "https://admin.example.com/panel",
        "bare path": "admin.example.com/panel",
        "trailing dot": "admin.example.com.",
        "upper case": "ADMIN.Example.COM",
        "userinfo": "https://ops@admin.example.com",
        "trailing comma": "admin.example.com,",
        "backticks": "`admin.example.com`",
    }

    def test_every_written_form_of_a_deny_rule_denies_the_host(self):
        for form, rule in self.DENY_FORMS.items():
            with self.subTest(form=form):
                scope = Scope(["example.com"], [rule])
                self.assertFalse(scope.in_scope_host("https://admin.example.com/"))
                self.assertFalse(scope.in_scope_host("https://admin.example.com:8443/panel"))
                self.assertTrue(scope.in_scope_host("https://api.example.com/"))

    def test_wildcard_deny_rule_written_as_url(self):
        scope = Scope(["example.com"], ["https://*.corp.example.com/"])
        self.assertFalse(scope.in_scope_host("https://vpn.corp.example.com/"))
        self.assertTrue(scope.in_scope_host("https://corp.example.com/"))

    def test_ipv6_cidr_deny_rule(self):
        scope = Scope(["re:.*"], ["2001:db8::/32"])
        self.assertFalse(scope.in_scope_host("http://[2001:db8::1]/"))
        self.assertTrue(scope.in_scope_host("http://[2001:db9::1]/"))

    def test_rules_from_scope_json_are_normalized(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"name": "acme", "in_scope": ["https://example.com/"],
                       "out_of_scope": ["https://admin.example.com:443/"]}, fh)
        try:
            scope = Scope.load(path)
        finally:
            os.remove(path)
        self.assertEqual(scope.in_scope, ["example.com"])
        self.assertEqual(scope.out_of_scope, ["admin.example.com"])
        self.assertFalse(scope.in_scope_host("https://admin.example.com/"))
        self.assertTrue(scope.in_scope_host("https://www.example.com/"))

    def test_port_bullet_in_scope_md_denies(self):
        fd, path = tempfile.mkstemp(suffix=".md")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("## In scope\n\n- example.com\n\n## Out of scope\n\n- admin.example.com:8443 — legacy panel\n")
        try:
            scope = _scope_from_md(path)
        finally:
            os.remove(path)
        self.assertFalse(scope.in_scope_host("https://admin.example.com:8443/"))


class InvalidDenyRegexTests(unittest.TestCase):
    def test_uncompilable_out_of_scope_regex_is_refused(self):
        with self.assertRaises(ValueError):
            Scope(["example.com"], ["re:^admin[.example\\.com$"])

    def test_uncompilable_in_scope_regex_warns_and_matches_nothing(self):
        scope = Scope(["re:^api[.example\\.com$"])
        self.assertFalse(scope.in_scope_host("https://api.example.com/"))
        self.assertEqual(len(scope.warnings), 1)

    def test_cli_exits_2_on_unenforceable_deny_rule(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = _main(["admin.example.com", "--in-scope", "example.com",
                          "--out-of-scope", "re:(unclosed"])
        self.assertEqual(code, 2)
        self.assertIn("scope error", err.getvalue())


class IpRuleTests(unittest.TestCase):
    def test_ipv6_cidr_and_exact_address_in_scope(self):
        scope = Scope(["2001:db8::/32", "[2001:db8:ffff::5]"])
        self.assertTrue(scope.in_scope_host("http://[2001:db8::1]:8080/"))
        self.assertTrue(scope.in_scope_host("http://[2001:0db8:0000::0001]/"))
        self.assertFalse(scope.in_scope_host("http://[2001:dead::1]/"))

    def test_cidr_written_as_url_keeps_its_prefix(self):
        # urlparse puts "/24" in the path; the rule must stay a network, not one IP
        for rule in ("https://192.168.1.0/24", "192.168.1.0/24/", "http://192.168.1.0:8080/24",
                     "`https://192.168.1.0/24`,"):
            with self.subTest(rule=rule):
                scope = Scope(["re:.*"], [rule])
                self.assertEqual(scope.out_of_scope, ["192.168.1.0/24"])
                self.assertFalse(scope.in_scope_host("http://192.168.1.5/"))
                self.assertTrue(scope.in_scope_host("http://192.168.2.5/"))
        scope = Scope(["re:.*"], ["https://[2001:db8::]/32"])
        self.assertEqual(scope.out_of_scope, ["2001:db8::/32"])
        self.assertFalse(scope.in_scope_host("http://[2001:db8::7]/"))

    def test_ip_with_a_real_path_is_widened_to_the_ip_and_warned(self):
        scope = Scope(["re:.*"], ["https://192.168.1.10/admin", "192.168.1.11/99"])
        self.assertEqual(scope.out_of_scope, ["192.168.1.10", "192.168.1.11"])
        self.assertEqual(len(scope.warnings), 2)

    def test_ipv4_rule_does_not_match_an_ipv6_host(self):
        self.assertFalse(Scope(["0.0.0.0/0"]).in_scope_host("http://[::1]/"))

    def test_ip_rules_never_match_hostnames(self):
        scope = Scope(["10.0.0.0/8", "127.0.0.1"])
        self.assertFalse(scope.in_scope_host("https://10.0.0.1.example.com/"))
        self.assertTrue(scope.in_scope_host("http://127.0.0.1:3000/"))


class WarningTests(unittest.TestCase):
    def test_widened_and_unmatchable_rules_are_reported(self):
        scope = Scope(["https://app.example.com/api", "api.*.example.com"],
                      ["admin.example.com:8443"])
        joined = "\n".join(scope.warnings)
        self.assertIn("in-scope rule 'https://app.example.com/api' names a path", joined)
        self.assertIn("in-scope rule 'api.*.example.com' is not a valid host", joined)
        self.assertIn("out-of-scope rule 'admin.example.com:8443' names a port 8443", joined)

    def test_plain_rules_produce_no_warnings(self):
        scope = Scope(["example.com", "*.example.org", "10.0.0.0/8", "re:^lab\\d+\\.x\\.io$"],
                      ["admin.example.com"])
        self.assertEqual(scope.warnings, [])

    def test_cli_prints_warnings_to_stderr(self):
        err = io.StringIO()
        with redirect_stderr(err), redirect_stdout(io.StringIO()):
            code = _main(["api.example.com", "--in-scope", "example.com",
                          "--out-of-scope", "admin.example.com:8443"])
        self.assertEqual(code, 0)
        self.assertIn("scope warning", err.getvalue())


if __name__ == "__main__":
    unittest.main()
