import subprocess
import unittest
from unittest.mock import patch

from eval import run_eval


class TargetResetTests(unittest.TestCase):
    def test_still_reachable_target_does_not_hide_failed_restart(self):
        failed = subprocess.CompletedProcess([], 1)
        with patch.object(run_eval.subprocess, "run", return_value=failed), patch.object(
            run_eval, "wait_ready", return_value=True
        ) as ready:
            self.assertFalse(run_eval.reset_target("target", "http://127.0.0.1:3001"))
            ready.assert_not_called()

    def test_successful_restart_is_followed_by_readiness_probe(self):
        succeeded = subprocess.CompletedProcess([], 0)
        with patch.object(run_eval.subprocess, "run", return_value=succeeded), patch.object(
            run_eval, "wait_ready", return_value=True
        ) as ready:
            self.assertTrue(run_eval.reset_target("target", "http://127.0.0.1:3001"))
            ready.assert_called_once_with("http://127.0.0.1:3001")

    def test_restart_timeout_fails_the_reset(self):
        timeout = subprocess.TimeoutExpired(["docker", "restart"], 60)
        with patch.object(run_eval.subprocess, "run", side_effect=timeout), patch.object(
            run_eval, "wait_ready"
        ) as ready:
            self.assertFalse(run_eval.reset_target("target", "http://127.0.0.1:3001"))
            ready.assert_not_called()
