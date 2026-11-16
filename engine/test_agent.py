import json
import subprocess
import unittest
from unittest.mock import patch

import agent


class AgentResultTests(unittest.TestCase):
    def run_result(self, returncode, **payload):
        completed = subprocess.CompletedProcess(
            args=["claude"], returncode=returncode,
            stdout=json.dumps(payload), stderr="",
        )
        with patch.object(agent.subprocess, "run", return_value=completed):
            return agent.run_agent("Synthetic task")

    def test_cli_error_result_remains_retryable(self):
        result = self.run_result(
            1, is_error=True, subtype="error_max_turns", total_cost_usd=0.01,
        )
        self.assertEqual(result["error"], "error_max_turns")
        self.assertEqual(result["cost_usd"], 0.01)

    def test_nonzero_exit_with_success_shaped_output_is_an_error(self):
        result = self.run_result(1, result="Partial output", is_error=False)
        self.assertEqual(result["error"], "exit:1")

    def test_api_error_with_zero_exit_is_an_error(self):
        result = self.run_result(0, result="API error", is_error=True)
        self.assertEqual(result["error"], "agent-error")

    def test_preserves_success_and_rate_limit_classification(self):
        self.assertIsNone(self.run_result(0, result="Completed")["error"])
        result = self.run_result(1, result="Usage limit reached", is_error=True)
        self.assertEqual(result["error"], "rate-limited")
