import json
import os
import time
import unittest

import agent_grok


class AllowlistTests(unittest.TestCase):
    def test_program_of(self):
        self.assertEqual(agent_grok._program_of("curl -s https://x/"), "curl")
        self.assertEqual(agent_grok._program_of("FOO=bar curl -s https://x/"), "curl")
        self.assertEqual(agent_grok._program_of("python3 -c 'print(1)'"), "python3")

    def test_refuses_disallowed_program(self):
        self.assertTrue(agent_grok._run_shell("rm -rf /", time.time() + 30).startswith("REFUSED"))
        self.assertTrue(agent_grok._run_shell("echo hi", time.time() + 30).startswith("REFUSED"))
        self.assertTrue(agent_grok._run_shell("bash -c 'curl x'", time.time() + 30).startswith("REFUSED"))

    def test_runs_allowed_program(self):
        out = agent_grok._run_shell('python3 -c "print(6*7)"', time.time() + 30)
        self.assertEqual(out.strip(), "42")

    def test_budget_exhausted(self):
        self.assertTrue(agent_grok._run_shell("curl x", time.time() - 5).startswith("REFUSED"))


class MissingKeyTests(unittest.TestCase):
    def test_missing_key_is_clear_error(self):
        saved = os.environ.pop("XAI_API_KEY", None)
        try:
            r = agent_grok.run_agent("noop")
            self.assertEqual(r["error"], "config:XAI_API_KEY not set")
            self.assertEqual(r["result"], "")
        finally:
            if saved is not None:
                os.environ["XAI_API_KEY"] = saved


class AgentLoopTests(unittest.TestCase):
    """Drive the whole loop with a mocked completion endpoint (no network)."""

    def setUp(self):
        self._saved = os.environ.get("XAI_API_KEY")
        os.environ["XAI_API_KEY"] = "test-key-not-real"
        self._real = agent_grok._chat_completion

    def tearDown(self):
        agent_grok._chat_completion = self._real
        if self._saved is None:
            os.environ.pop("XAI_API_KEY", None)
        else:
            os.environ["XAI_API_KEY"] = self._saved

    def test_tool_loop_then_verdict(self):
        calls = {"n": 0}

        def fake(messages, model, timeout):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"choices": [{"message": {"content": "", "tool_calls": [
                    {"id": "c1", "type": "function", "function": {
                        "name": "run_shell",
                        "arguments": json.dumps({"command": "python3 -c \"print('pong')\""})}}]}}],
                    "usage": {"total_tokens": 10}}
            tool_msgs = [m for m in messages if m.get("role") == "tool"]
            self.assertTrue(tool_msgs and "pong" in tool_msgs[-1]["content"])
            return {"choices": [{"message": {"content":
                '```json\n{"vulnerable": false, "severity": "low", "evidence": "none", '
                '"hosts_contacted": [], "proof_note": ""}\n```'}}],
                "usage": {"total_tokens": 12}}

        agent_grok._chat_completion = fake
        r = agent_grok.run_agent("task", max_turns=5, timeout=30)
        self.assertIsNone(r["error"])
        self.assertEqual(r["num_turns"], 2)
        self.assertEqual(r["tokens"], 22)
        verdict = agent_grok.extract_json(r["result"])
        self.assertEqual(verdict["vulnerable"], False)

    def test_rate_limit_classified(self):
        def fake(messages, model, timeout):
            raise RuntimeError("rate-limited:429 slow down")
        agent_grok._chat_completion = fake
        r = agent_grok.run_agent("task", max_turns=3, timeout=30)
        self.assertEqual(r["error"], "rate-limited")

    def test_max_turns_when_model_never_stops(self):
        def fake(messages, model, timeout):
            return {"choices": [{"message": {"content": "", "tool_calls": [
                {"id": "c", "type": "function", "function": {
                    "name": "run_shell",
                    "arguments": json.dumps({"command": "python3 -c \"print(1)\""})}}]}}],
                "usage": {"total_tokens": 1}}
        agent_grok._chat_completion = fake
        r = agent_grok.run_agent("task", max_turns=3, timeout=30)
        self.assertEqual(r["error"], "max-turns")
        self.assertEqual(r["num_turns"], 3)

    def test_unknown_tool_refused(self):
        calls = {"n": 0}

        def fake(messages, model, timeout):
            calls["n"] += 1
            if calls["n"] == 1:
                return {"choices": [{"message": {"content": "", "tool_calls": [
                    {"id": "c1", "type": "function", "function": {
                        "name": "delete_everything", "arguments": "{}"}}]}}]}
            tool_msgs = [m for m in messages if m.get("role") == "tool"]
            self.assertTrue(tool_msgs[-1]["content"].startswith("REFUSED"))
            return {"choices": [{"message": {"content": '```json\n{"real": false, "reason": "x"}\n```'}}]}

        agent_grok._chat_completion = fake
        r = agent_grok.run_agent("task", max_turns=4, timeout=30)
        self.assertIsNone(r["error"])


if __name__ == "__main__":
    unittest.main()
