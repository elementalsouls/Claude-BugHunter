import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cbh import cli


class ToolDiscoveryTests(unittest.TestCase):
    def test_missing_tool_does_not_need_a_which_executable(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"PATH": folder}):
            self.assertFalse(cli.has_cmd("subfinder"))

    def test_detects_executable_with_only_its_directory_on_path(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"PATH": folder}):
            name = "synthetic-subfinder.exe" if os.name == "nt" else "synthetic-subfinder"
            Path(folder, name).touch(mode=0o755)
            self.assertTrue(cli.has_cmd(name))
