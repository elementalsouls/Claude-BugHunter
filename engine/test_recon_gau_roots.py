"""recon._gau_urls must use scope-aware enumeration roots instead of truncating
seeds to their last two labels (which queried public suffixes like `co.uk` and
garbage IP fragments like `0.1`).
"""
import unittest
from unittest.mock import patch

import recon
from scope import Scope


class GauRootsTests(unittest.TestCase):
    def _run_gau(self, scope):
        queried = []

        class FakeProc:
            stdout = ""

        def fake_run(cmd, **kwargs):
            queried.append(cmd[1])
            return FakeProc()

        with patch.object(recon, "which", return_value="/usr/bin/gau"), \
             patch("subprocess.run", side_effect=fake_run):
            recon._gau_urls(scope, log=lambda *a: None)
        return queried

    def test_multi_label_tld_is_not_truncated_to_public_suffix(self):
        scope = Scope(in_scope=["*.example.co.uk"], seeds=["https://app.example.co.uk/"])
        self.assertEqual(self._run_gau(scope), ["example.co.uk"])

    def test_ip_seeds_do_not_invoke_gau_on_octets(self):
        scope = Scope(in_scope=["10.0.0.0/8"], seeds=["http://10.0.0.1:8080/"])
        self.assertEqual(self._run_gau(scope), [])

    def test_exact_regex_scope_uses_full_seed_hostname(self):
        scope = Scope(in_scope=[r"re:^portal\.example\.com\.au$"],
                      seeds=["https://portal.example.com.au/"])
        self.assertEqual(self._run_gau(scope), ["portal.example.com.au"])


if __name__ == "__main__":
    unittest.main()
