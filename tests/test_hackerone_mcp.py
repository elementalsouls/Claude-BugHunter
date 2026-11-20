"""Tests for the HackerOne MCP server (mcp/hackerone/server.py).

No network: urllib.request.urlopen is mocked. Covers the JSON-RPC lifecycle,
credential-gated tool listing, error codes, GraphQL-injection escaping, and the
authenticated path (parsing + bounded pagination) that cannot be reached live
without a real token.
"""
import importlib.util
import io
import json
import os
import unittest
from unittest.mock import patch

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SERVER = os.path.join(_REPO, "mcp", "hackerone", "server.py")
_spec = importlib.util.spec_from_file_location("cbh_h1_mcp", _SERVER)
h1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h1)


class _Resp:
    """Minimal stand-in for the urlopen context manager."""
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _urlopen_returning(payload):
    return lambda req, timeout=None: _Resp(payload)


def _urlopen_raising(code):
    def _raise(req, timeout=None):
        err = h1.urllib.error.HTTPError(getattr(req, "full_url", "x"), code, "", {},
                                        io.BytesIO(b""))
        err.close()  # avoid a ResourceWarning from the unclosed body fp
        raise err
    return _raise


NO_CREDS = {k: v for k, v in os.environ.items()
            if k not in ("HACKERONE_API_USERNAME", "HACKERONE_API_TOKEN")}
CREDS = dict(NO_CREDS, HACKERONE_API_USERNAME="u", HACKERONE_API_TOKEN="t")


class LifecycleTests(unittest.TestCase):
    def test_initialize_echoes_supported_version(self):
        r = h1._handle_request({"method": "initialize",
                                "params": {"protocolVersion": "2025-03-26"}})
        self.assertEqual(r["protocolVersion"], "2025-03-26")
        self.assertIn("tools", r["capabilities"])
        self.assertEqual(r["serverInfo"]["name"], "hackerone")

    def test_initialize_rejects_unsupported_version(self):
        r = h1._handle_request({"method": "initialize",
                                "params": {"protocolVersion": "2099-01-01"}})
        self.assertEqual(r["protocolVersion"], h1.PROTOCOL_VERSION)

    def test_ping(self):
        self.assertEqual(h1._handle_request({"method": "ping"}), {})

    def test_unknown_method_raises_lookuperror(self):
        with self.assertRaises(LookupError):
            h1._handle_request({"method": "resources/list"})


class ToolGatingTests(unittest.TestCase):
    def test_public_only_without_credentials(self):
        with patch.dict(os.environ, NO_CREDS, clear=True):
            names = [s["name"] for s, _ in h1._tools()]
        self.assertEqual(names, ["search_disclosed_reports", "get_program",
                                 "get_program_scope", "get_report"])

    def test_auth_tools_appear_with_credentials(self):
        with patch.dict(os.environ, CREDS, clear=True):
            names = [s["name"] for s, _ in h1._tools()]
        self.assertIn("list_my_reports", names)
        self.assertEqual(len(names), 7)

    def test_calling_auth_tool_without_creds_is_invalid_params(self):
        with patch.dict(os.environ, NO_CREDS, clear=True):
            with self.assertRaises(h1.InvalidParams):
                h1._handle_request({"method": "tools/call",
                                    "params": {"name": "list_my_reports", "arguments": {}}})


class PublicToolTests(unittest.TestCase):
    def test_search_parses_nodes(self):
        payload = {"data": {"search": {"total_count": 1, "nodes": [{
            "report": {"title": "SSRF in x", "url": "https://hackerone.com/reports/1"},
            "team": {"handle": "acme"}, "severity_rating": "High",
            "total_awarded_amount": 500, "votes": 3}]}}}
        with patch.object(h1.urllib.request, "urlopen", _urlopen_returning(payload)):
            out = h1.search_disclosed_reports({"query": "ssrf", "program": "acme"})
        self.assertEqual(out["returned"], 1)
        self.assertEqual(out["reports"][0]["severity"], "high")

    def test_search_requires_query_or_program(self):
        with self.assertRaises(h1.ToolError):
            h1.search_disclosed_reports({})

    def test_graphql_error_becomes_toolerror(self):
        with patch.object(h1.urllib.request, "urlopen",
                          _urlopen_returning({"errors": [{"message": "boom"}]})):
            with self.assertRaises(h1.ToolError):
                h1.get_program({"program": "acme"})


class EscapingTests(unittest.TestCase):
    def test_quote_in_program_is_escaped_not_broken_out(self):
        captured = {}

        def fake(req, timeout=None):
            captured["body"] = req.data.decode()
            return _Resp({"data": {"team": {"handle": "x"}}})

        with patch.object(h1.urllib.request, "urlopen", fake):
            h1.get_program({"program": 'a" injected'})
        # decode the JSON envelope, then check the GraphQL query string itself:
        # the input double-quote is escaped (\") so it can't close the handle literal.
        query = json.loads(captured["body"])["query"]
        self.assertIn('a\\" injected', query)
        self.assertNotIn('a" injected', query)  # no unescaped breakout


class LimitTests(unittest.TestCase):
    def test_limit_clamped_and_coerced(self):
        self.assertEqual(h1._limit({"limit": 999}), h1.MAX_LIMIT)
        self.assertEqual(h1._limit({"limit": 0}), 1)

    def test_limit_non_numeric_is_toolerror(self):
        with self.assertRaises(h1.ToolError):
            h1._limit({"limit": "abc"})


class AuthPathTests(unittest.TestCase):
    def test_list_my_reports_omits_phantom_substate(self):
        page = {"data": [{"id": "1", "attributes": {
            "title": "t", "state": "triaged", "substate": "SHOULD_NOT_APPEAR",
            "created_at": "2026-01-01", "disclosed_at": None}, "relationships": {}}], "links": {}}
        with patch.dict(os.environ, CREDS, clear=True), \
             patch.object(h1.urllib.request, "urlopen", _urlopen_returning(page)):
            out = h1.list_my_reports({})
        self.assertEqual(out["reports"][0]["state"], "triaged")
        self.assertNotIn("substate", out["reports"][0])

    def test_pagination_terminates_on_empty_data_with_next(self):
        # The infinite-loop trap: zero rows but a non-null `next`. Must stop, not hang.
        trap = {"data": [], "links": {"next": "https://api.hackerone.com/v1/hackers/me/reports?x=1"}}
        with patch.dict(os.environ, CREDS, clear=True), \
             patch.object(h1.urllib.request, "urlopen", _urlopen_returning(trap)):
            out = h1.list_my_reports({})
        self.assertEqual(out["reports"], [])

    def test_pagination_page_cap_bounds_calls(self):
        # Non-empty rows plus an always-present `next` → the hard page cap must stop it.
        calls = {"n": 0}

        def fake(req, timeout=None):
            calls["n"] += 1
            return _Resp({"data": [{"id": str(calls["n"]), "attributes": {}, "relationships": {}}],
                          "links": {"next": "https://api.hackerone.com/v1/hackers/programs?p=1"}})

        with patch.dict(os.environ, CREDS, clear=True), \
             patch.object(h1.urllib.request, "urlopen", fake):
            h1.list_my_programs({"limit": 10_000})
        self.assertLessEqual(calls["n"], h1._MAX_PAGES)


_FULL_REPORT = {
    "id": 826361, "url": "https://hackerone.com/reports/826361",
    "title": "SSRF in import", "severity_rating": "high", "substate": "resolved",
    "is_published": True, "disclosed_at": "2020-03-01T00:00:00.000Z",
    "has_bounty?": True, "formatted_bounty": "$10,000",
    "vulnerability_information": "x" * 4576,
    # sensitive keys that MUST be dropped from the whitelist:
    "reporter": {"username": "secret"}, "team": {"handle": "acme"},
    "voters": [1, 2], "is_triager?": False, "can_view_report": True,
    "abilities": {}, "attachments": [],
}


class GetReportTests(unittest.TestCase):
    def test_full_body_whitelist(self):
        with patch.object(h1.urllib.request, "urlopen", _urlopen_returning(_FULL_REPORT)):
            out = h1.get_report({"id": 826361})
        self.assertEqual(out["id"], 826361)
        self.assertEqual(out["severity"], "high")
        self.assertEqual(out["substate"], "resolved")
        self.assertEqual(out["bounty"], "$10,000")
        self.assertEqual(out["body_len"], 4576)
        self.assertNotIn("note", out)

    def test_sensitive_keys_excluded(self):
        with patch.object(h1.urllib.request, "urlopen", _urlopen_returning(_FULL_REPORT)):
            out = h1.get_report({"url": "https://hackerone.com/reports/826361"})
        for k in ("reporter", "team", "voters", "is_triager?", "can_view_report",
                  "abilities", "attachments"):
            self.assertNotIn(k, out)

    def test_empty_body_gets_note_and_no_bounty(self):
        thin = dict(_FULL_REPORT, vulnerability_information="")
        thin["has_bounty?"] = False
        with patch.object(h1.urllib.request, "urlopen", _urlopen_returning(thin)):
            out = h1.get_report({"id": 1189367})
        self.assertEqual(out["body_len"], 0)
        self.assertIn("note", out)
        self.assertNotIn("bounty", out)

    def test_404_raises_toolerror(self):
        with patch.object(h1.urllib.request, "urlopen", _urlopen_raising(404)):
            with self.assertRaises(h1.ToolError):
                h1.get_report({"id": 99})

    def test_bad_input_raises_toolerror(self):
        # bad arguments use the same recoverable ToolError channel as every other tool
        for args in ({}, {"id": 1, "url": "https://hackerone.com/reports/2"},
                     {"id": "../etc"},
                     {"url": "https://hackerone.com/reports/notanumber"},
                     {"url": "https://hackerone.com/reports/826361/activity"},
                     {"id": "²"},   # superscript 2: isdigit() True but int() would raise
                     {"id": "٣"},   # Arabic-Indic 3: isdigit() True but not our report id
                     {"id": "-5"}):
            with self.assertRaises(h1.ToolError):
                h1.get_report(args)

    def test_url_variants_parse_to_id(self):
        for u in ("https://hackerone.com/reports/826361",
                  "https://hackerone.com/reports/826361/",
                  "https://hackerone.com/reports/826361?x=1",
                  "https://hackerone.com/reports/826361#foo"):
            with patch.object(h1.urllib.request, "urlopen", _urlopen_returning(_FULL_REPORT)):
                out = h1.get_report({"url": u})
            self.assertEqual(out["id"], 826361)


if __name__ == "__main__":
    unittest.main()
