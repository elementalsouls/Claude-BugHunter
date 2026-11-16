import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup_harness_mcp.py"


class HarnessConfigTest(unittest.TestCase):
    def test_invalid_json_shapes_leave_files_intact_and_do_not_block_codex(self):
        for bad_config in ("[]", '{"mcp":null}', '{"mcp":[]}', "{"):
            with self.subTest(bad_config=bad_config), tempfile.TemporaryDirectory() as tmp:
                home = Path(tmp)
                opencode = home / ".config/opencode/opencode.json"
                opencode.parent.mkdir(parents=True)
                opencode.write_text(bad_config, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "--opencode", "--codex", "--command", "fixture"],
                    capture_output=True,
                    text=True,
                    env={**os.environ, "HOME": tmp, "USERPROFILE": tmp},
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("OpenCode: cannot update", result.stdout)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(opencode.read_text(encoding="utf-8"), bad_config)
                self.assertIn(
                    'command = "fixture"',
                    (home / ".codex/config.toml").read_text(encoding="utf-8"),
                )
