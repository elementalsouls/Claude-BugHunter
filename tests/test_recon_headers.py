import unittest
from unittest.mock import patch

from cbh import cli


class ReconHeaderTests(unittest.TestCase):
    def test_live_probe_accepts_headers_with_arbitrary_casing(self):
        headers = {
            "server": "synthetic",
            "X-POWERED-BY": "fixture",
            "x-drupal-cache": "HIT",
        }
        with patch.object(cli, "http_get", return_value=(200, headers, "<title>Demo</title>")):
            result = cli.recon_http_probe("example.test")
        self.assertEqual(result["server"], "synthetic")
        self.assertEqual(result["powered_by"], "fixture")
        self.assertEqual(result["drupal_cache"], "HIT")
