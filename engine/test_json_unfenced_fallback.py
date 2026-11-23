import unittest

import agent


class UnfencedJSONFallbackTests(unittest.TestCase):
    """When the agent omits the requested ```json fence, extract_json must still
    return the last top-level JSON value, even if a brace appears earlier."""

    def test_request_body_before_verdict(self):
        text = ("I sent curl -d '{\"id\": 6}' to the endpoint and got 403.\n"
                '{"vulnerable": false, "severity": "low"}')
        self.assertEqual(agent.extract_json(text), {"vulnerable": False, "severity": "low"})

    def test_two_objects_last_wins(self):
        self.assertEqual(agent.extract_json('{"a": 1} and then {"b": 2}'), {"b": 2})

    def test_non_json_brace_before_verdict(self):
        self.assertEqual(agent.extract_json('template {x} then {"vulnerable": true}'),
                         {"vulnerable": True})

    def test_top_level_array_is_not_reduced_to_inner_object(self):
        self.assertEqual(agent.extract_json('result: [{"vulnerable": true}]'),
                         [{"vulnerable": True}])

    def test_deeply_nested_unclosed_brackets_do_not_raise(self):
        self.assertEqual(agent.extract_json("[" * 3000 + ' {"vulnerable": true}'),
                         {"vulnerable": True})

    def test_truncated_json_is_none(self):
        self.assertIsNone(agent.extract_json('broken {"a": 1'))


if __name__ == "__main__":
    unittest.main()
