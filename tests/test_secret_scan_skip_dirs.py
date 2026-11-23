"""secret_scan must prune noisy directories by exact name BELOW the root, and
always scan the root it was handed. The old substring check (`part in root`)
matched the whole walked path including the root, so `secret_scan ./dist`,
`.github/` (contains `.git`), or `nightly-builds/` printed nothing and exited 0 —
a false "clean" in a leak guard. Reported in #216."""
import importlib.util
import os
import unittest
from pathlib import Path

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SS = os.path.join(_REPO, "skills", "offensive-osint", "scripts", "secret_scan.py")
_spec = importlib.util.spec_from_file_location("secret_scan", _SS)
secret_scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(secret_scan)

_SECRET = "AKIAIOSFODNN7EXAMPLE"  # AWS access-key-id shape, triggers a high-sev pattern


def _hits(path):
    return [f for f in secret_scan.scan_path(str(path))]


class SecretScanSkipDirTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _seed(self, rel):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"key = {_SECRET}\n", encoding="utf-8")

    def test_root_named_like_a_skip_dir_is_still_scanned(self):
        # user explicitly points the scanner at ./dist — it must scan it
        self._seed("dist/app/config.env")
        self.assertTrue(_hits(self.root / "dist"), "root 'dist' was silently skipped")

    def test_dotgithub_root_is_scanned(self):
        # '.github' contains the substring '.git' but is not a skip dir
        self._seed(".github/workflows/leak.yml")
        self.assertTrue(_hits(self.root / ".github"), "'.github' silently skipped via '.git' substring")

    def test_skip_dirs_below_root_still_pruned(self):
        self._seed("node_modules/pkg/x.js")
        self._seed(".git/config")
        self._seed("venv/lib/y.py")
        self._seed("src/real.py")  # the only one that should be reported
        hits = _hits(self.root)
        sources = " ".join(h["source"] for h in hits)
        self.assertIn("real.py", sources)
        self.assertNotIn("node_modules", sources)
        self.assertNotIn(os.sep + ".git" + os.sep, sources)
        self.assertNotIn("venv", sources)


if __name__ == "__main__":
    unittest.main()
