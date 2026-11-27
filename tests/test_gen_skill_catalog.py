"""gen_skill_catalog --check must flag a stale docs/skills.md without touching it."""
import contextlib
import importlib.util
import io
import os
import pathlib
import tempfile
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "gen_skill_catalog", os.path.join(_REPO, "scripts", "gen_skill_catalog.py"))
gsc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gsc)


class CatalogCheckTests(unittest.TestCase):
    def test_check_write_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "skills.md")
            with open(out, "w", encoding="utf-8") as fh:
                fh.write("stale\n")
            old, gsc.OUT = gsc.OUT, out
            try:
                err = io.StringIO()
                with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(gsc.main(["--check"]), 1)
                    self.assertEqual(pathlib.Path(out).read_text(encoding="utf-8"), "stale\n")
                    self.assertIn("run python3 scripts/gen_skill_catalog.py", err.getvalue())
                    self.assertEqual(gsc.main([]), 0)
                    self.assertEqual(pathlib.Path(out).read_text(encoding="utf-8"), gsc.render())
                    self.assertEqual(gsc.main(["--check"]), 0)
            finally:
                gsc.OUT = old

    def test_moved_skills_not_in_other(self):
        page = gsc.render()
        other = page.split("## Other")[1] if "## Other" in page else ""
        for n in ("regression-hunting", "exploit-completion"):
            self.assertNotIn(f"`{n}`", other)


if __name__ == "__main__":
    unittest.main()
