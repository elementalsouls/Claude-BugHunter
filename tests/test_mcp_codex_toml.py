import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.setup_harness_mcp import write_codex

try:
    import tomllib
except ImportError:
    tomllib = None


@unittest.skipUnless(tomllib, "TOML parsing requires Python 3.11+")
class CodexTomlTests(unittest.TestCase):
    def test_config_round_trips_arguments_and_literal_environment_keys(self):
        command = "synthetic-mcp"
        args = ['one "quoted" argument', "line\nbreak", "\tmarker\x7f", "café"]
        env = {"app.setting": "value", "RESEARCH_LABEL": "fixture\nsecond line"}

        with tempfile.TemporaryDirectory() as home:
            with patch.dict(os.environ, {"HOME": home, "USERPROFILE": home}):
                write_codex(command, args, env, dry=False)
            config = Path(home) / ".codex" / "config.toml"
            parsed = tomllib.loads(config.read_text(encoding="utf-8"))

        self.assertEqual(
            parsed["mcp_servers"]["burp"],
            {"command": command, "args": args, "env": env},
        )
