import json
import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

from eval import run_eval


class AgentFailureTests(unittest.TestCase):
    def test_failed_agent_payload_is_not_scorable(self):
        cases = [
            (1, True, "exit:1"),
            (0, True, "error response"),
            (0, False, None),
        ]
        for code, is_error, expected in cases:
            payload = {
                "is_error": is_error,
                "result": "VERDICT: VULNERABLE",
                "total_cost_usd": 0.02,
            }
            completed = CompletedProcess([], code, json.dumps(payload), "")
            with self.subTest(code=code, is_error=is_error), patch.object(
                run_eval.subprocess, "run", return_value=completed
            ):
                result = run_eval.run_agent("fixture", False, "model", 1, 1)
                self.assertEqual(result.get("agent_error"), expected)
                self.assertEqual(result["cost_usd"], 0.02)
                self.assertEqual(result["result"], "" if expected else payload["result"])

    def test_missing_cli_is_a_failed_row(self):
        with patch.object(run_eval.subprocess, "run", side_effect=FileNotFoundError):
            result = run_eval.run_agent("fixture", False, "model", 1, 1)
        self.assertEqual(result["agent_error"], "launch:FileNotFoundError")
