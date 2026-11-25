import json
import tempfile
import unittest
from pathlib import Path
from server import snapshot, engagements

class DashboardTests(unittest.TestCase):
    def test_summary_only(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/"demo"
            p.mkdir()
            state=p/"state.json"
            state.write_text(json.dumps({"phase":"hunt","surface":[{"url":"secret.example"}],"tested":["private"],"confirmed":[{"verdict":{"severity":"high"},"evidence":"secret"}]}),encoding="utf-8")
            result=snapshot(state)
            self.assertEqual(result["surface"],1)
            self.assertEqual(result["tested"],1)
            self.assertEqual(result["severity"],{"high":1})
            self.assertNotIn("secret",json.dumps(result))
            self.assertEqual(engagements(Path(root)),["demo"])

if __name__=="__main__":
    unittest.main()
