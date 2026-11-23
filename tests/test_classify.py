import unittest

from cbh.cli import classify_url


class ClassifyUrlTests(unittest.TestCase):
    def test_hostname_does_not_trigger_path_patterns(self):
        # Hostnames containing keywords should not trigger path-based pattern matches (issue #218)
        false_positive_urls = [
            "https://verify.example.com/home",
            "https://cart.shop.example/products",
            "https://admin.example.com/dashboard",
        ]
        for url in false_positive_urls:
            with self.subTest(url=url):
                res = classify_url(url)
                self.assertEqual(res["matches"], {})

    def test_legitimate_path_patterns_match(self):
        self.assertIn("hunt-mfa-bypass", classify_url("https://example.com/verify")["matches"])
        self.assertIn("hunt-business-logic", classify_url("https://example.com/cart?x=1")["matches"])
        self.assertIn("hunt-business-logic", classify_url("/checkout")["matches"])
        self.assertIn("hunt-auth-bypass", classify_url("example.com/login")["matches"])

    def test_query_parameters_match(self):
        self.assertIn("hunt-ssrf", classify_url("https://example.com?url=https://other.com")["matches"])
        self.assertIn("hunt-xss", classify_url("https://example.com/search?q=test")["matches"])
        matches = classify_url("https://example.com/app?next=/login")["matches"]
        self.assertIn("hunt-ssrf", matches)
        self.assertIn("hunt-auth-bypass", matches)
