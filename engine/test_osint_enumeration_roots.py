from unittest import TestCase
from unittest.mock import Mock, patch

import osint
from engine import Engine
from scope import Scope


class EnumerationRootTests(TestCase):
    def test_roots_follow_authorized_domains(self):
        cases = [
            (["*.example.co.uk"], ["https://example.co.uk"], ["example.co.uk"]),
            (["*.example.com"], ["https://api.example.com"], ["example.com"]),
            (["app.example.com"], ["https://app.example.com"], ["app.example.com"]),
            (["127.0.0.1", "::1"], ["http://127.0.0.1", "http://[::1]"], []),
            (["re:.*example.com", "example.com/path", "example.com:8080"], [], []),
            ([], ["https://App.Example.COM./"], ["app.example.com"]),
            (["*.EXAMPLE.COM.", "api.example.com"], ["https://v1.api.example.com"],
             ["api.example.com", "example.com"]),
            ([], [], []),
            ([], ["http://[invalid"], []),
        ]
        for patterns, seeds, expected in cases:
            with self.subTest(patterns=patterns, seeds=seeds):
                self.assertEqual(osint.enumeration_roots(Scope(patterns, seeds=seeds)), expected)

    def test_osint_queries_only_authorized_root(self):
        scope = Scope(["*.example.co.uk"], seeds=["https://example.co.uk"])
        with patch.object(osint, "enumerate_subdomains", return_value=set()) as enumerate_hosts, \
             patch.object(osint, "probe_hosts", return_value=([], "fake")) as probe:
            osint.osint(scope, log=Mock())
        self.assertEqual([call.args[0] for call in enumerate_hosts.call_args_list], ["example.co.uk"])
        self.assertEqual(probe.call_args.args[0], [])

    def test_expand_queries_only_authorized_root(self):
        runner = Engine.__new__(Engine)
        runner.scope = Scope(["*.example.co.uk"], seeds=["https://example.co.uk"])
        runner.eng = Mock()
        with patch.object(osint, "enumerate_subdomains", return_value={"app.example.co.uk"}) as enumerate_hosts, \
             patch.object(osint, "probe_hosts", return_value=([
                 {"url": "https://app.example.co.uk"}
             ], "fake")) as probe:
            runner._expand_scope()
        self.assertEqual([call.args[0] for call in enumerate_hosts.call_args_list], ["example.co.uk"])
        self.assertEqual(probe.call_args.args[0], ["app.example.co.uk"])
        self.assertEqual(runner.scope.seeds, ["https://app.example.co.uk"])
