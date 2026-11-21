"""Tests for skills/offensive-osint/scripts/h1_reference.py.

No network: urllib.request.urlopen is mocked with synthetic data only.
Covers --program query_string filtering, pagination, sorting, GraphQL escaping,
stderr routing for lookup progress, and clean --json stdout output.
"""
import argparse
import importlib.util
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPT = os.path.join(_REPO, "skills", "offensive-osint", "scripts", "h1_reference.py")
_spec = importlib.util.spec_from_file_location("cbh_h1_reference_test", _SCRIPT)
h1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h1)


class _Resp:
    """Minimal stand-in for the urlopen context manager."""

    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _make_args(**overrides):
    defaults = {
        "program": None,
        "program_id": None,
        "top_voted": False,
        "top_bounty": False,
        "query": None,
        "severity": None,
        "cwe": None,
        "limit": 20,
        "pages": 1,
        "json": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _synthetic_node(report_id, title, handle="acme-test", votes=10, bounty=None):
    return {
        "id": f"doc-{report_id}",
        "severity_rating": "high",
        "total_awarded_amount": bounty,
        "currency": "USD",
        "cwe": "CWE-918",
        "cve_ids": [],
        "votes": votes,
        "team": {"handle": handle, "name": "Acme Test"},
        "reporter": {"username": "researcher-1"},
        "report": {
            "_id": str(report_id),
            "title": title,
            "url": f"https://hackerone.com/reports/{report_id}",
        },
    }


class BuildPageQueryTests(unittest.TestCase):
    def test_program_filter_uses_query_string_team_handle_not_team_id(self):
        args = _make_args(program="acme-test", program_id="9999")
        query = h1.build_page_query(args)
        self.assertIn('query_string: "team_handle:acme-test"', query)
        self.assertNotIn("team_id", query)
        self.assertIn("total_count", query)
        self.assertIn("pageInfo { endCursor }", query)
        self.assertIn("nodes {", query)

    def test_program_filter_with_cursor_preserves_after_pagination(self):
        args = _make_args(program="acme-test")
        query = h1.build_page_query(args, after="NTA=")
        self.assertIn('query_string: "team_handle:acme-test"', query)
        self.assertIn('after: "NTA="', query)

    def test_program_filter_with_sort_flags_includes_sort(self):
        voted = h1.build_page_query(_make_args(program="acme-test", top_voted=True))
        self.assertIn('query_string: "team_handle:acme-test"', voted)
        self.assertIn('sort: {field: "votes", direction: DESC}', voted)

        bounty = h1.build_page_query(_make_args(program="acme-test", top_bounty=True))
        self.assertIn('query_string: "team_handle:acme-test"', bounty)
        self.assertIn('sort: {field: "total_awarded_amount", direction: DESC}', bounty)

    def test_program_filter_escapes_quotes_and_backslashes(self):
        args = _make_args(program='acme"\\test')
        query = h1.build_page_query(args)
        self.assertIn('query_string: "team_handle:acme\\"\\\\test"', query)
        self.assertNotIn('team_handle:acme"', query)

    def test_negative_control_sort_only_without_program_unchanged(self):
        query = h1.build_page_query(_make_args(top_voted=True))
        self.assertIn("query: {bool: {}}", query)
        self.assertIn('sort: {field: "votes", direction: DESC}', query)
        self.assertNotIn("query_string", query)
        self.assertNotIn("team_handle:", query)

    def test_negative_control_default_without_program_or_sort_unchanged(self):
        query = h1.build_page_query(_make_args())
        self.assertIn('terms: {substate: ["resolved"]}', query)
        self.assertNotIn("query_string", query)
        self.assertNotIn("team_handle:", query)


class LookupProgramOutputTests(unittest.TestCase):
    def test_lookup_program_writes_progress_to_stderr_not_stdout(self):
        payload = {
            "data": {
                "team": {
                    "id": "gid-synthetic",
                    "_id": "9999",
                    "handle": "acme-test",
                    "name": "Acme Test",
                    "url": "https://hackerone.com/acme-test",
                }
            }
        }
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(h1.urllib.request, "urlopen", return_value=_Resp(payload)), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            team_id = h1.lookup_program("acme-test")
        self.assertEqual(team_id, "9999")
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("[+] acme-test", stderr.getvalue())
        self.assertIn("id=9999", stderr.getvalue())

    def test_lookup_program_missing_writes_error_to_stderr_and_returns_none(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(h1.urllib.request, "urlopen", return_value=_Resp({"data": {"team": None}})), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            team_id = h1.lookup_program("missing-prog")
        self.assertIsNone(team_id)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("not found or is private", stderr.getvalue())

    def test_lookup_program_null_data_returns_none_cleanly(self):
        payload = {"data": None, "errors": [{"message": "synthetic error"}]}
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(h1.urllib.request, "urlopen", return_value=_Resp(payload)), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            team_id = h1.lookup_program("acme-test")
        self.assertIsNone(team_id)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("not found or is private", stderr.getvalue())


class MainCliTests(unittest.TestCase):
    def test_program_with_json_produces_clean_parseable_stdout(self):
        captured_queries = []
        responses = [
            {
                "data": {
                    "team": {
                        "id": "gid-synthetic",
                        "_id": "9999",
                        "handle": "acme-test",
                        "name": "Acme Test",
                        "url": "https://hackerone.com/acme-test",
                    }
                }
            },
            {
                "data": {
                    "search": {
                        "total_count": 1,
                        "pageInfo": {"endCursor": None},
                        "nodes": [_synthetic_node(101, "Synthetic SSRF in importer")],
                    }
                }
            },
        ]

        def fake_urlopen(req, timeout=None):
            captured_queries.append(json.loads(req.data.decode("utf-8"))["query"])
            return _Resp(responses.pop(0))

        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["h1_reference.py", "--program", "acme-test", "--json"]), \
             patch.object(h1.urllib.request, "urlopen", side_effect=fake_urlopen), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            h1.main()

        parsed = json.loads(stdout.getvalue())
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["report"]["_id"], "101")
        self.assertIn("[+] acme-test", stderr.getvalue())
        self.assertEqual(len(captured_queries), 2)
        self.assertIn('query_string: "team_handle:acme-test"', captured_queries[1])
        self.assertNotIn("team_id", captured_queries[1])

    def test_program_pagination_follows_end_cursor(self):
        captured_queries = []
        responses = [
            {
                "data": {
                    "team": {
                        "id": "gid-synthetic",
                        "_id": "9999",
                        "handle": "acme-test",
                        "name": "Acme Test",
                        "url": "https://hackerone.com/acme-test",
                    }
                }
            },
            {
                "data": {
                    "search": {
                        "total_count": 2,
                        "pageInfo": {"endCursor": "MQ=="},
                        "nodes": [_synthetic_node(101, "Synthetic finding one", votes=5)],
                    }
                }
            },
            {
                "data": {
                    "search": {
                        "total_count": 2,
                        "pageInfo": {"endCursor": None},
                        "nodes": [_synthetic_node(102, "Synthetic finding two", votes=15)],
                    }
                }
            },
        ]

        def fake_urlopen(req, timeout=None):
            captured_queries.append(json.loads(req.data.decode("utf-8"))["query"])
            return _Resp(responses.pop(0))

        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(
            sys,
            "argv",
            ["h1_reference.py", "--program", "acme-test", "--pages", "2", "--limit", "5", "--top-voted", "--json"],
        ), \
             patch.object(h1.urllib.request, "urlopen", side_effect=fake_urlopen), \
             patch.object(h1.time, "sleep"), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            h1.main()

        parsed = json.loads(stdout.getvalue())
        self.assertEqual([item["report"]["_id"] for item in parsed], ["102", "101"])
        self.assertEqual(len(captured_queries), 3)
        self.assertIn('query_string: "team_handle:acme-test"', captured_queries[1])
        self.assertIn('query_string: "team_handle:acme-test"', captured_queries[2])
        self.assertIn('after: "MQ=="', captured_queries[2])

    def test_invalid_program_not_found_exits_nonzero_with_empty_stdout(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["h1_reference.py", "--program", "missing-prog", "--json"]), \
             patch.object(h1.urllib.request, "urlopen", return_value=_Resp({"data": {"team": None}})), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as ctx:
                h1.main()
        self.assertEqual(ctx.exception.code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("missing-prog", stderr.getvalue())

    def test_empty_or_whitespace_program_exits_nonzero_without_network_call(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["h1_reference.py", "--program", "   ", "--json"]), \
             patch.object(h1.urllib.request, "urlopen") as mock_urlopen, \
             redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as ctx:
                h1.main()
        self.assertEqual(ctx.exception.code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("--program", stderr.getvalue())
        mock_urlopen.assert_not_called()

    def test_client_sort_works_with_program_handle_without_program_id(self):
        nodes = [
            _synthetic_node(101, "Low votes", votes=3),
            _synthetic_node(102, "High votes", votes=42),
        ]
        args = argparse.Namespace(program="acme-test", top_voted=True, top_bounty=False)
        sorted_nodes = h1.client_sort(nodes, args)
        self.assertEqual([n["report"]["_id"] for n in sorted_nodes], ["102", "101"])


if __name__ == "__main__":
    unittest.main()
