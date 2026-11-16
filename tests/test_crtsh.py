import io
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from cbh import cli


class CertificateTransparencyTests(unittest.TestCase):
    def lookup(self, body):
        stderr = io.StringIO()
        with patch.object(cli, "http_get", return_value=(200, {}, body)), redirect_stderr(stderr):
            result = cli.recon_subdomains_via_crtsh("example.test")
        return result, stderr.getvalue()

    def test_error_object_warns_and_allows_recon_fallback(self):
        result, warning = self.lookup('{"error": "service unavailable"}')
        self.assertEqual(result, set())
        self.assertIn("INCOMPLETE", warning)

    def test_malformed_rows_do_not_discard_valid_names(self):
        result, warning = self.lookup(
            '[null, {"name_value": 42}, {"name_value": "WWW.EXAMPLE.TEST\\n*.example.test"}]'
        )
        self.assertEqual(result, {"www.example.test"})
        self.assertIn("INCOMPLETE", warning)

    def test_empty_response_is_a_valid_result(self):
        result, warning = self.lookup("[]")
        self.assertEqual(result, set())
        self.assertEqual(warning, "")
