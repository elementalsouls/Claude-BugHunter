import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ENGINE_DIR = Path(__file__).resolve().parent


class PhaseArgumentTests(unittest.TestCase):
    def test_invalid_phase_lists_fail_before_creating_state(self):
        for phases in ("", ",", "map,hutn"):
            with self.subTest(phases=phases), tempfile.TemporaryDirectory() as base:
                result = subprocess.run(
                    [sys.executable, str(ENGINE_DIR / "engine.py"), "--mock",
                     "--scope", str(ENGINE_DIR / "engagement.example.json"),
                     "--base", base, "--phases", phases],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("--phases", result.stderr)
                self.assertEqual(list(Path(base).iterdir()), [])
