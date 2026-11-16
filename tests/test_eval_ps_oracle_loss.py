import unittest
from unittest.mock import patch

from eval import run_eval_ps_auto as auto, run_eval_ps_par as parallel


class OracleLossTests(unittest.TestCase):
    def test_post_run_oracle_loss_is_unscored(self):
        lab = {"key": "synthetic", "objective": "fixture"}
        url = "https://example.invalid"
        for runner in (auto, parallel):
            with self.subTest(runner=runner.__name__), patch.object(
                runner, "ps_solved", side_effect=[(False, True), (None, False)]
            ), patch.object(runner.RE, "run_agent", return_value={"cost_usd": 0.1}), patch.object(
                runner.time, "sleep"
            ):
                if runner is auto:
                    record, = runner.run_one(lab, url, ["baseline"], "model", 1, 1)
                else:
                    record = runner.do_run(lab, url, "baseline", "model", 1, 1)
                self.assertIsNone(record["solved"])
                self.assertFalse(record["oracle_ok"])
                self.assertEqual(record["cost_usd"], 0.1)
