"""Unfenced extract_json must keep the LAST top-level JSON value, not one greedy
brace-to-brace span. A reply with an earlier brace — `curl -d '{"id":6}' ...
{"vulnerable":true}` — made the greedy `\\{.*\\}` span unparseable, so the verdict
was lost and the item re-ran with no verdict. Reported in #217."""
import unittest

from agent import extract_json


class UnfencedFallbackTests(unittest.TestCase):
    def test_earlier_brace_does_not_swallow_final_verdict(self):
        text = 'ran: curl -d \'{"id": 6}\' https://x/a\n\n{"vulnerable": true, "severity": "high"}'
        self.assertEqual(extract_json(text), {"vulnerable": True, "severity": "high"})

    def test_last_of_several_objects_wins(self):
        text = '{"step": 1} then {"step": 2} finally {"verdict": "confirmed"}'
        self.assertEqual(extract_json(text), {"verdict": "confirmed"})

    def test_array_still_extracted(self):
        self.assertEqual(extract_json('noise {"a":1}\n[{"b":2}]'), [{"b": 2}])

    def test_fenced_block_still_preferred(self):
        text = '{"loose": 1}\n```json\n{"fenced": 2}\n```'
        self.assertEqual(extract_json(text), {"fenced": 2})

    def test_no_json_returns_none(self):
        self.assertIsNone(extract_json("no json at all here"))

    def test_single_object_unchanged(self):
        self.assertEqual(extract_json('text {"x": "y"} more'), {"x": "y"})


if __name__ == "__main__":
    unittest.main()
