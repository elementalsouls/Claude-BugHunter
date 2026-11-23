#!/usr/bin/env python3
"""The agents' rules of engagement must carry the out-of-scope (deny) list.

A bare in-scope rule like `example.com` covers every subdomain, so an agent that
is only told "example.com is in scope" has no way to know `admin.example.com` is
excluded. The code gate (Scope.in_scope_host) denies it, but the hunt/validate
agents follow links and craft their own requests; _scope_audit only flags the
contact after it has happened.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import engine  # noqa: E402
from scope import Scope  # noqa: E402


def _runner(scope, intrusive=False):
    r = engine.Engine.__new__(engine.Engine)
    r.scope = scope
    r.allow_intrusive = intrusive
    return r


class RoeOutOfScopeTests(unittest.TestCase):
    def test_excluded_hosts_are_in_the_agent_prompt(self):
        scope = Scope(["example.com"], ["admin.example.com", "payments.example.com"])
        self.assertFalse(scope.in_scope_host("https://admin.example.com"))  # the gate denies it
        roe = _runner(scope)._roe()
        for host in ("admin.example.com", "payments.example.com"):
            self.assertIn(host, roe, f"{host} is out of scope but the agent is never told")
        self.assertIn("EXCLUDED", roe)

    def test_prompt_explains_bare_domain_covers_subdomains(self):
        roe = _runner(Scope(["example.com"]))._roe()
        self.assertIn("subdomains", roe)

    def test_no_exclusion_line_when_there_is_no_deny_list(self):
        roe = _runner(Scope(["example.com"]))._roe()
        self.assertNotIn("EXCLUDED", roe)

    def test_exclusions_are_present_in_intrusive_mode_too(self):
        roe = _runner(Scope(["example.com"], ["admin.example.com"]), intrusive=True)._roe()
        self.assertIn("admin.example.com", roe)


if __name__ == "__main__":
    unittest.main()
