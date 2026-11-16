import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import agent


class BurpConfigTests(unittest.TestCase):
    def command(self, path):
        completed = subprocess.CompletedProcess(["claude"], 0, stdout='{"result":"done"}')
        with patch.object(agent, "MCP_CONFIG", str(path)), patch.object(
            agent.subprocess, "run", return_value=completed,
        ) as run:
            agent.run_agent("Synthetic task")
        return run.call_args.args[0]

    def test_missing_config_runs_without_mcp_servers(self):
        with tempfile.TemporaryDirectory() as temp:
            command = self.command(Path(temp) / "burp-mcp.json")
        config = command[command.index("--mcp-config") + 1]
        tools = command[command.index("--allowedTools") + 1]
        self.assertEqual(json.loads(config), {"mcpServers": {}})
        self.assertNotIn("mcp__burp", tools)
        self.assertIn("Bash(curl:*)", tools)
        self.assertIn("--strict-mcp-config", command)

    def test_existing_config_keeps_burp_tools(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "burp-mcp.json"
            path.touch()
            command = self.command(path)
        self.assertEqual(command[command.index("--mcp-config") + 1], str(path))
        self.assertIn("mcp__burp__send_http1_request", command[command.index("--allowedTools") + 1])
