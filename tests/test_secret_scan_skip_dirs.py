"""scan_path must skip noisy directories by exact name below the requested root,
not by a substring of the whole path. Before the fix, `secret_scan.py ./dist`,
`.github/` (contains ".git") or `nightly-builds/` (contains "build") printed nothing.
"""
import importlib.util
import os
import tempfile
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SS = os.path.join(_REPO, "skills", "offensive-osint", "scripts", "secret_scan.py")
_spec = importlib.util.spec_from_file_location("secret_scan", _SS)
ss = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ss)

KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented example key id


class ScanPathSkipDirsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, rel):
        p = os.path.join(self.tmp, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(f'const k = "{KEY}";\n')

    def _hits(self, rel_root):
        return [h["source"] for h in ss.scan_path(os.path.join(self.tmp, *rel_root.split("/")))]

    def test_requested_root_is_scanned_even_if_its_name_is_in_the_skip_list(self):
        self._write("dist/main.js")
        self._write("build/main.js")
        self.assertEqual(len(self._hits("dist")), 1)
        self.assertEqual(len(self._hits("build")), 1)

    def test_names_that_only_contain_a_skip_word_are_scanned(self):
        self._write("nightly-builds/main.js")
        self._write(".github/workflows/ci.yml")
        self._write("redistributable/main.js")
        self.assertEqual(len(self._hits("nightly-builds")), 1)
        self.assertEqual(len(self._hits(".github")), 1)
        self.assertEqual(len(self._hits("redistributable")), 1)

    def test_skip_dirs_below_the_root_are_still_pruned(self):
        self._write("src/app.js")
        self._write("src/node_modules/pkg/index.js")
        self._write("src/.git/config")
        self._write("src/venv/lib/x.py")
        self._write("src/dist/main.js")
        hits = self._hits("src")
        self.assertEqual(hits, [os.path.join(self.tmp, "src", "app.js")])


if __name__ == "__main__":
    unittest.main()
