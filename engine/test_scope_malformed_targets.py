import unittest

from scope import Scope


class MalformedTargetTests(unittest.TestCase):
    def test_malformed_urls_are_out_of_scope_without_interrupting_batch(self):
        rule = Scope(["example.test"])
        for malformed in ("https://[example.test", "https://example.test]/"):
            with self.subTest(malformed=malformed):
                self.assertFalse(rule.in_scope_host(malformed))
                self.assertEqual(rule.reject_reason(malformed), "could not parse host")
        self.assertTrue(rule.in_scope_host("https://api.example.test/"))
