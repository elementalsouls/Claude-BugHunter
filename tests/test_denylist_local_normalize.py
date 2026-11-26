"""The gitignored scripts/.identifier-denylist.local holds plaintext names that both
leak guards (scan_identifiers.py, lint_skills.py) hash at runtime. Each entry must be
normalized the way shingles() tokenizes scanned text, or a name written with
punctuation ("Example-Corp", "example.io") hashes to a value no shingle can equal and
the guard silently passes the leak. An entry longer than the 2-word shingle window
can never match, so it must fail closed instead of being loaded as a dead hash."""
import contextlib
import importlib.util
import io
import os
import tempfile
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_REPO, "scripts", f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class LocalDenylistNormalizationTests(unittest.TestCase):
    def _denylist(self, mod, local_body):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".identifier-denylist.local"), "w", encoding="utf-8") as fh:
                fh.write(local_body)
            orig = mod.SCRIPTS_DIR
            mod.SCRIPTS_DIR = tmp
            try:
                return mod.load_denylist()
            finally:
                mod.SCRIPTS_DIR = orig

    def test_punctuated_names_are_caught_by_both_guards(self):
        for mod in (_load("scan_identifiers"), _load("lint_skills")):
            deny = self._denylist(mod, "# comment\nExample-Corp\nexample.io\n")
            for text in ("Engagement for Example-Corp (prod)", "see example.io/admin"):
                hits = [s for s in mod.shingles(text)
                        if mod.hashlib.sha256(s.encode()).hexdigest() in deny]
                self.assertTrue(hits, (mod.__name__, text))

    def test_entry_longer_than_the_shingle_window_fails_closed(self):
        for mod in (_load("scan_identifiers"), _load("lint_skills")):
            err = io.StringIO()
            with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(err):
                self._denylist(mod, "Big Example Bank\n")
            self.assertEqual(cm.exception.code, 2)
            self.assertIn(":1", err.getvalue())
            self.assertNotIn("Big Example Bank", err.getvalue())


if __name__ == "__main__":
    unittest.main()
