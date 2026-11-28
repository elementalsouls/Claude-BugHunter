"""An out-of-scope rule with a `*` inside the host must exclude its hosts.

`_match` only understood a leading `*.`, so `staging-*.example.com` or
`www.*.example.com` in `## Out of scope` matched nothing and the hosts stayed
in scope under an in-scope `*.example.com`.
"""
import os
import tempfile
import unittest

from scope import Scope, _scope_from_md


class MidLabelWildcardDenyTests(unittest.TestCase):
    def test_midlabel_deny_rules_exclude_their_hosts(self):
        s = Scope(in_scope=["*.example.com"],
                  out_of_scope=["staging-*.example.com", "www.*.example.com",
                                "*.*.corp.example.com"])
        for host in ("staging-1.example.com", "staging-eu.example.com",
                     "www.eu.example.com", "a.b.corp.example.com"):
            with self.subTest(host=host):
                self.assertFalse(s.in_scope_host("https://" + host + "/"))
                self.assertIn("out-of-scope", s.reject_reason("https://" + host + "/"))
        for host in ("api.example.com", "staging.example.com", "www.example.com"):
            with self.subTest(host=host):
                self.assertTrue(s.in_scope_host("https://" + host + "/"))

    def test_midlabel_deny_rule_from_scope_md(self):
        md = ("# Scope\n\n## In scope\n- *.example.com\n\n"
              "## Out of scope\n- staging-*.example.com\n")
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False,
                                         encoding="utf-8") as fh:
            fh.write(md)
        try:
            s = _scope_from_md(fh.name)
        finally:
            os.unlink(fh.name)
        self.assertFalse(s.in_scope_host("https://staging-1.example.com/"))
        self.assertTrue(s.in_scope_host("https://api.example.com/"))

    def test_plain_rules_are_unchanged(self):
        s = Scope(in_scope=["example.com"],
                  out_of_scope=["*.admin.example.com", "10.0.0.0/8", "internal.example.com"])
        self.assertEqual(s.out_of_scope,
                         ["*.admin.example.com", "10.0.0.0/8", "internal.example.com"])


if __name__ == "__main__":
    unittest.main()
