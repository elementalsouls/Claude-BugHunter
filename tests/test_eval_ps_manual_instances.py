import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from eval import run_eval_ps


class ManualPortSwiggerTests(unittest.TestCase):
    def test_duplicate_instance_hostname_fails_before_oracle_or_agent(self):
        lab = {
            "key": "fixture",
            "objective": "fixture",
            "instances": {
                "skills": "https://ABC.web-security-academy.net",
                "baseline": "https://abc.web-security-academy.net:443/",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp, "labs.json")
            out = Path(tmp, "runs.jsonl")
            config.write_text(json.dumps([lab]), encoding="utf-8")
            args = ["run_eval_ps.py", "--labs", str(config), "--out", str(out)]
            with patch.object(sys, "argv", args), patch.object(
                run_eval_ps, "ps_solved", return_value=(None, False)
            ) as oracle, patch.object(run_eval_ps.RE, "run_agent") as agent, \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                with self.assertRaises(SystemExit) as error:
                    run_eval_ps.main()
            self.assertEqual(error.exception.code, 2)
            self.assertIn("fixture / skills", stderr.getvalue())
            self.assertIn("fixture / baseline", stderr.getvalue())
            oracle.assert_not_called()
            agent.assert_not_called()
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
