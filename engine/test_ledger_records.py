import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import memory


class LedgerRecordsTests(unittest.TestCase):
    def test_valid_json_with_wrong_shape_cannot_poison_lookup(self):
        finding = {"host": "example.test", "url": "https://example.test/items",
                   "vuln_class": "idor", "param": "id", "severity": "low"}
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"BUGHUNTER_MEMORY_DIR": folder}):
            path = Path(folder, "findings.jsonl")
            path.write_text("null\n[]\n42\n" + json.dumps(finding) + "\n", encoding="utf-8")
            result = memory.skip_decision("example.test", [], finding)
            self.assertEqual(result["reason"], "known-confirmed")
