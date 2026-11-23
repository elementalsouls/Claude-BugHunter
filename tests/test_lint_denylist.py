"""lint_skills.load_denylist shares the leak guard's denylist file and had the
same fail-open as scan_identifiers (#212): a malformed .sha256 entry was loaded
verbatim as a hash that matches nothing, so the skill linter would pass skills
that leak a banned identifier whose denylist line is broken. It must fail closed."""
import importlib.util
import io
import os
import contextlib
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LS = os.path.join(_REPO, "scripts", "lint_skills.py")
_spec = importlib.util.spec_from_file_location("lint_skills", _LS)
lint_skills = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lint_skills)


class LintDenylistValidationTests(unittest.TestCase):
    def _write_denylist(self, tmp, body):
        scripts = os.path.join(tmp, "scripts")
        os.makedirs(scripts, exist_ok=True)
        with open(os.path.join(scripts, ".identifier-denylist.sha256"), "w", encoding="utf-8") as fh:
            fh.write(body)
        return scripts

    def test_valid_digests_load(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            good = "a" * 64
            scripts = self._write_denylist(tmp, f"# header\n{good}\n")
            orig = lint_skills.SCRIPTS_DIR
            lint_skills.SCRIPTS_DIR = scripts
            try:
                self.assertEqual(lint_skills.load_denylist(), {good})
            finally:
                lint_skills.SCRIPTS_DIR = orig

    def test_malformed_entry_fails_closed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            scripts = self._write_denylist(tmp, "# header\n" + "a" * 64 + "\nnot-a-digest\n")
            orig = lint_skills.SCRIPTS_DIR
            lint_skills.SCRIPTS_DIR = scripts
            err = io.StringIO()
            try:
                with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(err):
                    lint_skills.load_denylist()
            finally:
                lint_skills.SCRIPTS_DIR = orig
            self.assertEqual(cm.exception.code, 2)
            self.assertIn(":3", err.getvalue())
            self.assertNotIn("not-a-digest", err.getvalue())


if __name__ == "__main__":
    unittest.main()
