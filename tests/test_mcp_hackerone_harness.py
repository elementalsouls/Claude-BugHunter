import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.setup_harness_mcp import hackerone_source, write_codex, write_antigravity

try:
    import tomllib
except ImportError:
    tomllib = None


class HackeroneSourceTests(unittest.TestCase):
    def test_source_points_at_repo_server_and_is_keyless_by_default(self):
        clean = {k: v for k, v in os.environ.items()
                 if k not in ("HACKERONE_API_USERNAME", "HACKERONE_API_TOKEN")}
        with patch.dict(os.environ, clean, clear=True):
            cmd, args, env = hackerone_source()
        self.assertEqual(cmd, "python3")
        self.assertEqual(len(args), 1)
        self.assertTrue(args[0].endswith(os.path.join("mcp", "hackerone", "server.py")))
        self.assertTrue(os.path.isfile(args[0]))  # the server really exists at that path
        self.assertEqual(env, {})

    def test_source_carries_credentials_when_set(self):
        with patch.dict(os.environ, {"HACKERONE_API_USERNAME": "u", "HACKERONE_API_TOKEN": "t"}):
            _, _, env = hackerone_source()
        self.assertEqual(env, {"HACKERONE_API_USERNAME": "u", "HACKERONE_API_TOKEN": "t"})


@unittest.skipUnless(tomllib, "TOML parsing requires Python 3.11+")
class HackeroneWiringTests(unittest.TestCase):
    def test_codex_entry_uses_hackerone_key_not_burp(self):
        with tempfile.TemporaryDirectory() as home:
            with patch.dict(os.environ, {"HOME": home, "USERPROFILE": home}):
                write_codex("python3", ["/x/server.py"], {}, dry=False, name="hackerone")
            parsed = tomllib.loads((Path(home) / ".codex" / "config.toml").read_text("utf-8"))
        self.assertIn("hackerone", parsed["mcp_servers"])
        self.assertNotIn("burp", parsed["mcp_servers"])
        self.assertEqual(parsed["mcp_servers"]["hackerone"]["command"], "python3")

    def test_antigravity_entry_uses_hackerone_key(self):
        with tempfile.TemporaryDirectory() as home:
            with patch.dict(os.environ, {"HOME": home, "USERPROFILE": home}):
                write_antigravity("python3", ["/x/server.py"], {}, dry=False, name="hackerone")
            cfg = json.loads((Path(home) / ".gemini/config/mcp_config.json").read_text("utf-8"))
        self.assertIn("hackerone", cfg["mcpServers"])


if __name__ == "__main__":
    unittest.main()
