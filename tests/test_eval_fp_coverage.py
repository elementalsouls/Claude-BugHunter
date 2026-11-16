import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from eval import run_fp


class FpCoverageTests(unittest.TestCase):
    def test_unscored_responses_do_not_count_as_correct_negatives(self):
        cases = [
            {"key": "graded", "ground": "safe"},
            {"key": "empty", "ground": "safe"},
            {"key": "no_control", "ground": "vulnerable"},
        ]

        def classify(case, _base, condition, *_):
            is_positive = case["key"] == "graded"
            return {
                "case": case["key"],
                "condition": condition,
                "ground": case["ground"],
                "verdict": "VULNERABLE" if is_positive else "NO_OUTPUT",
                "false_positive": is_positive,
                "true_positive": False,
            }

        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp, "cases.json")
            config.write_text(json.dumps(cases))
            argv = [
                "run_fp.py", "--cases", str(config), "--out", str(Path(tmp, "run.jsonl")),
                "--conditions", "baseline", "--parallel", "1",
            ]
            out = io.StringIO()
            with patch("sys.argv", argv), patch.object(
                run_fp.urllib.request, "urlopen"
            ), patch.object(run_fp, "do_case", side_effect=classify), redirect_stdout(out):
                run_fp.main()
        self.assertIn("false-positives 1/1 (FPR 100%)", out.getvalue())
        self.assertIn("true-positives 0/0 (TPR n/a)", out.getvalue())
        self.assertIn("coverage: 1/2 safe, 0/1 vulnerable", out.getvalue())
