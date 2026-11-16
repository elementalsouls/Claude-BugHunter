import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import engine


class VerdictTests(unittest.TestCase):
    def setUp(self):
        self.runner = engine.Engine.__new__(engine.Engine)
        self.runner.mock = False
        self.runner.model = "synthetic"
        self.runner.max_turns = 1
        self.runner.timeout = 1
        self.runner._roe = lambda: ""
        self.runner.eng = SimpleNamespace(state={}, log=Mock())
        self.item = {"url": "https://example.test/", "vuln_class": "cors"}

    def verdict(self, method, payload):
        with patch.object(engine.A, "run_agent", return_value={"result": json.dumps(payload)}):
            return method(self.item)

    def test_malformed_hunt_verdicts_stay_on_worklist(self):
        for payload in ({"vulnerable": "false"}, {"severity": "high"}, [{"vulnerable": True}]):
            with self.subTest(payload=payload):
                self.assertTrue(self.verdict(self.runner._hunt_agent, payload)["errored"])

    def test_malformed_validation_verdicts_are_inconclusive(self):
        for payload in ({"real": "false"}, {}, [{"real": True}]):
            with self.subTest(payload=payload):
                result = self.verdict(self.runner._validate_agent, payload)
                self.assertTrue(result["errored"])
                self.assertFalse(result["real"])

    def test_boolean_verdicts_are_preserved(self):
        for flag in (True, False):
            self.assertEqual(self.verdict(self.runner._hunt_agent, {"vulnerable": flag}), {"vulnerable": flag})
            self.assertEqual(self.verdict(self.runner._validate_agent, {"real": flag}), {"real": flag})
