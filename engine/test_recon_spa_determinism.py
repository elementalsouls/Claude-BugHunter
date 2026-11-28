#!/usr/bin/env python3
"""spa_recon must mine the same JS bundles on every run.

js_urls is a set; taking list(js_urls)[:max_js] mined a different,
hash-seed-dependent subset whenever a page had more than max_js bundles,
so routes silently appeared and disappeared between runs. Sorting the
bundle URLs first makes the mined subset deterministic, as the docstring
("Deterministically map the in-scope surface") promises.
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(__file__))
import recon  # noqa: E402
from scope import Scope  # noqa: E402


class SpaReconDeterminismTests(unittest.TestCase):
    def _run(self, n_bundles=25, max_js=20):
        scope = Scope(["app.example.com"], seeds=["https://app.example.com/"])
        html = "<html>" + "".join(
            f'<script src="/static/bundle{i:02d}.js"></script>'
            for i in range(1, n_bundles + 1)
        ) + "</html>"

        def fake_get(url, timeout=20, allow=None):
            if url == "https://app.example.com/":
                return html, url, {}
            if url.endswith(".js"):
                n = url.split("bundle")[1].split(".js")[0]
                return f'fetch("/api/route{n}")', url, {}
            return "", url, {}

        with patch.object(recon, "_get", fake_get):
            items, _ = recon.spa_recon(scope, max_js=max_js, log=lambda *a, **k: None)
        return sorted(it["url"] for it in items)

    def test_mines_sorted_first_twenty_bundles(self):
        routes = self._run()
        self.assertEqual(
            routes,
            [f"https://app.example.com/api/route{i:02d}" for i in range(1, 21)],
        )

    def test_repeated_runs_mine_the_same_routes(self):
        self.assertEqual(self._run(), self._run())


if __name__ == "__main__":
    unittest.main()
