"""build_page_query must filter programs with query_string:team_handle, not the
team_id terms filter the H1 schema no longer accepts (#206, #202).

No network: build_page_query is a pure string builder over an args namespace.
"""
import argparse
import importlib.util
import os
import unittest
from unittest.mock import patch

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_H1 = os.path.join(_REPO, "skills", "offensive-osint", "scripts", "h1_reference.py")
_spec = importlib.util.spec_from_file_location("h1_reference", _H1)
h1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h1)


def _args(program=None, program_id=None, top_voted=False, top_bounty=False):
    return argparse.Namespace(program=program, program_id=program_id,
                              top_voted=top_voted, top_bounty=top_bounty)


class BuildPageQueryTests(unittest.TestCase):
    def test_program_uses_team_handle_not_team_id(self):
        q = h1.build_page_query(_args(program="acme", program_id="123"))
        self.assertIn("query_string:", q)
        self.assertIn("team_handle:acme", q)
        self.assertNotIn("team_id", q)

    def test_program_with_sort_adds_server_side_sort(self):
        q = h1.build_page_query(_args(program="acme", program_id="123", top_voted=True))
        self.assertIn("team_handle:acme", q)
        self.assertIn('field: "votes"', q)

    def test_sort_only_has_no_substate_filter(self):
        q = h1.build_page_query(_args(top_bounty=True))
        self.assertIn('field: "total_awarded_amount"', q)
        self.assertNotIn("substate", q)

    def test_default_mode_filters_resolved_without_team_id(self):
        q = h1.build_page_query(_args())
        self.assertIn('substate: ["resolved"]', q)
        self.assertNotIn("team_id", q)


class LookupProgramTests(unittest.TestCase):
    def test_returns_team_with_canonical_handle(self):
        # TeamLookup is case-insensitive; the caller needs the canonical handle
        # because the hacktivity query_string is not.
        resp = {"data": {"team": {"_id": "42", "handle": "shopify", "name": "Shopify"}}}
        with patch.object(h1, "gql_vars", return_value=resp):
            team = h1.lookup_program("Shopify")
        self.assertEqual(team["handle"], "shopify")
        self.assertEqual(team["_id"], "42")

    def test_returns_none_when_private_or_missing(self):
        with patch.object(h1, "gql_vars", return_value={"data": {"team": None}}):
            self.assertIsNone(h1.lookup_program("nope"))


if __name__ == "__main__":
    unittest.main()
