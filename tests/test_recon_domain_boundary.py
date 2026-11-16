import argparse
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cbh import cli


class ReconDomainBoundaryTests(unittest.TestCase):
    def test_only_valid_names_under_the_target_reach_dns_and_http(self):
        args = argparse.Namespace(target="Example.TEST.", proxy=None, burp=False)
        with tempfile.TemporaryDirectory() as scratch:
            args.out = scratch
            with patch.object(cli, "configure_proxy_from_args"), redirect_stdout(io.StringIO()):
                with patch.multiple(
                    cli,
                    recon_subdomains_via_crtsh=lambda _target: {
                        "www.example.test", "example.test.unrelated.test", "unrelated.test",
                    },
                    recon_subdomains_via_subfinder=lambda _target: {
                        "API.Example.Test.", "notexample.test", "invalid name.example.test",
                    },
                ):
                    with patch.object(cli, "recon_resolve", return_value=["192.0.2.1"]) as resolve:
                        with patch.object(cli, "recon_http_probe", return_value=None) as probe:
                            self.assertEqual(cli.cmd_recon(args), 0)
            expected = {"example.test", "www.example.test", "api.example.test"}
            self.assertEqual({call.args[0] for call in resolve.call_args_list}, expected)
            self.assertEqual({call.args[0] for call in probe.call_args_list}, expected)
            output = Path(scratch) / "example.test" / "subdomains.txt"
            self.assertEqual(set(output.read_text().splitlines()), expected)

    def test_url_and_path_targets_stop_before_passive_lookup(self):
        for target in ("https://example.test/", "example.test/path", "example.test:443"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as scratch:
                args = argparse.Namespace(target=target, out=scratch)
                with patch.object(cli, "recon_subdomains_via_crtsh") as lookup:
                    with redirect_stderr(io.StringIO()):
                        self.assertEqual(cli.cmd_recon(args), 1)
                lookup.assert_not_called()
                self.assertEqual(list(Path(scratch).iterdir()), [])
