import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from eval import run_eval


class JuiceShopOracleTests(unittest.TestCase):
    def test_unknown_or_malformed_challenges_are_unreadable(self):
        for payload in (
            {"data": None},
            {"data": [{"name": "fixture"}]},
            {"data": [{"name": "fixture", "solved": "false"}]},
            {"data": [{"name": "other", "solved": True}]},
        ):
            with self.subTest(payload=payload), patch.object(
                run_eval.urllib.request, "urlopen", return_value=contextlib.nullcontext(
                    io.StringIO(json.dumps(payload))
                )
            ):
                self.assertEqual(run_eval.oracle("http://localhost", "fixture"), (None, False))

    def test_oracle_loss_preserves_attempt_without_counting_a_miss(self):
        challenge = {"key": "fixture", "category": "test", "objective": "fixture",
                     "oracle_name": "fixture"}
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp, "challenges.json")
            output = Path(tmp, "results.jsonl")
            config.write_text(json.dumps([challenge]), encoding="utf-8")
            args = ["run_eval.py", "--challenges", str(config), "--out", str(output),
                    "--conditions", "baseline"]
            with patch.object(sys, "argv", args), patch.object(
                run_eval, "reset_target", return_value=True
            ), patch.object(
                run_eval, "oracle", side_effect=[(False, True), (None, False)]
            ), patch.object(
                run_eval, "run_agent", return_value={"cost_usd": 0.25}
            ), patch.object(run_eval.time, "sleep"), contextlib.redirect_stdout(io.StringIO()) as stdout:
                run_eval.main()

            row = json.loads(output.read_text(encoding="utf-8"))
            self.assertIsNone(row["solved"])
            self.assertFalse(row["oracle_ok"])
            self.assertIn("solved 0/0", stdout.getvalue())
            self.assertIn("total $0.25", stdout.getvalue())
            self.assertIn("1 oracle-unreadable", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
