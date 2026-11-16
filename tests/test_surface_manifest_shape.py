import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from cbh import cli


class SurfaceManifestShapeTests(unittest.TestCase):
    def test_wrong_shape_returns_a_diagnostic_instead_of_traceback(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp, "manifest.json")
            args = argparse.Namespace(target="example.test", manifest=str(manifest))
            for payload in ([], {"counts": None}, {"ranked_surface": {}}, {"ranked_surface": [None]}):
                with self.subTest(payload=payload), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as stderr:
                    manifest.write_text(json.dumps(payload), encoding="utf-8")
                    self.assertEqual(cli.cmd_surface(args), 1)
                    self.assertIn("invalid recon manifest", stderr.getvalue())
