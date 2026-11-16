import os
import tempfile
import unittest
from unittest.mock import patch

import memory


class LedgerObservationTests(unittest.TestCase):
    def test_regenerating_a_report_does_not_multiply_negative_evidence(self):
        finding = {"url": "https://example.test/x", "vuln_class": "cors", "param": "id"}
        tested = ["https://example.test/x|id|cors"]
        stack = ["synthetic-framework"]
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"BUGHUNTER_MEMORY_DIR": folder}):
            for _ in range(memory.DEAD_CLASS_THRESHOLD):
                memory.record_run("engagement-retry", stack, tested, [])
            self.assertFalse(memory.skip_decision("example.test", stack, finding)["skip"])
            for index in range(memory.DEAD_CLASS_THRESHOLD - 1):
                memory.record_run(f"independent-{index}", stack, tested, [])
            self.assertTrue(memory.skip_decision("example.test", stack, finding)["skip"])
