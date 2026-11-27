"""Tests for the scope-aware CLI check command."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cbh import scope_check


class ScopeCheckTests(unittest.TestCase):
    def test_markdown_scope_admits_allowed_and_denies_others(self):
        with tempfile.TemporaryDirectory() as folder:
            scope_md = Path(folder) / "scope.md"
            scope_md.write_text(
                "## In scope\n- example.com\n\n## Out of scope\n- admin.example.com\n",
                encoding="utf-8",
            )
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = scope_check.check_targets(
                    ["https://www.example.com/", "https://admin.example.com/"],
                    md=str(scope_md),
                )
            self.assertEqual(result, 1)
            self.assertIn("IN-SCOPE", stdout.getvalue())
            self.assertIn("OUT-OF-SCOPE", stdout.getvalue())
            self.assertIn("matches an out-of-scope rule", stdout.getvalue())

    def test_json_scope_returns_success_for_allowed_targets(self):
        with tempfile.TemporaryDirectory() as folder:
            scope_json = Path(folder) / "scope.json"
            scope_json.write_text(json.dumps({"in_scope": ["example.com"]}), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = scope_check.check_targets(["api.example.com"], scope_file=str(scope_json))
            self.assertEqual(result, 0)
            self.assertIn("IN-SCOPE", stdout.getvalue())

    def test_invalid_source_combination_is_rejected(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = scope_check.check_targets(["example.com"])
        self.assertEqual(result, 2)
        self.assertIn("exactly one scope source", stderr.getvalue())

    def test_scripts_entrypoint_dispatches_scope_check(self):
        # The public clone shim must route this subcommand instead of sending it to
        # argparse's legacy scope-import-only parser.
        import runpy
        from unittest.mock import patch

        with patch("cbh.scope_check.main", return_value=7) as run_check:
            with patch("sys.argv", ["scripts/cbh.py", "scope", "check", "--md", "scope.md", "example.com"]):
                with self.assertRaises(SystemExit) as exc:
                    runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "cbh.py"),
                                   run_name="__main__")
        self.assertEqual(exc.exception.code, 7)
        run_check.assert_called_once_with(["--md", "scope.md", "example.com"])


if __name__ == "__main__":
    unittest.main()
