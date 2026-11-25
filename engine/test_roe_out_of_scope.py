"""The agents' rules of engagement must carry the out-of-scope (deny) list (#226).

A bare in-scope rule like `example.com` covers every subdomain, so an agent told
only "example.com is in scope" has no way to know `admin.example.com` is excluded.
The code gate (Scope.in_scope_host) denies it, but the hunt/validate agents follow
links and craft their own requests, and _scope_audit only flags the contact after
it has already happened. The exclusions must be in the prompt up front.
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
        self.assertFalse(scope.in_scope_host("https://admin.example.com"))  # gate denies it
        roe = _runner(scope)._roe()
        for host in ("admin.example.com", "payments.example.com"):
            self.assertIn(host, roe, f"{host} is out of scope but the agent is never told")
        self.assertIn("EXCLUDED", roe)

    def test_prompt_explains_bare_domain_covers_subdomains(self):
        self.assertIn("subdomains", _runner(Scope(["example.com"]))._roe())

    def test_no_exclusion_line_when_there_is_no_deny_list(self):
        self.assertNotIn("EXCLUDED", _runner(Scope(["example.com"]))._roe())

    def test_exclusions_present_in_intrusive_mode_too(self):
        roe = _runner(Scope(["example.com"], ["admin.example.com"]), intrusive=True)._roe()
        self.assertIn("admin.example.com", roe)


if __name__ == "__main__":
    unittest.main()
