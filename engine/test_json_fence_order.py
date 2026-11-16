import unittest

import agent


class JSONFenceOrderTests(unittest.TestCase):
    def test_later_labeled_verdict_wins_over_earlier_unlabeled_example(self):
        text = '```\n{"real": true}\n```\nFinal decision: ```json\n{"real": false}\n```'
        self.assertEqual(agent.extract_json(text), {"real": False})

    def test_later_unlabeled_verdict_wins_over_earlier_labeled_example(self):
        text = '```json\n{"real": false}\n```\nFinal decision: ```\n{"real": true}\n```'
        self.assertEqual(agent.extract_json(text), {"real": True})
