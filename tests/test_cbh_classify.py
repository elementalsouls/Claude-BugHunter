"""classify_url must match URL_PATTERN_TO_SKILLS against the path/query, not the
hostname. A keyword living in the host (`verify.example.com`, `cart.shop.example`)
is not a request target and must not trigger a path-based skill. Reported in #219
(issue #218)."""
import unittest

from cbh import cli


def _pattern_hits(url):
    """Skills matched via a URL-pattern rationale (not the looser keyword signal)."""
    matches = cli.classify_url(url)["matches"]
    return {s for s, why in matches.items() if any("URL matches" in w for w in why)}


class ClassifyUrlTargetTests(unittest.TestCase):
    def test_keyword_in_hostname_does_not_trigger_path_skill(self):
        self.assertNotIn("hunt-mfa-bypass", _pattern_hits("https://verify.example.com/home"))
        self.assertNotIn("hunt-business-logic", _pattern_hits("https://cart.shop.example/products"))

    def test_keyword_in_path_still_triggers(self):
        self.assertIn("hunt-mfa-bypass", _pattern_hits("https://example.com/verify"))
        self.assertIn("hunt-business-logic", _pattern_hits("https://example.com/cart"))

    def test_query_param_still_triggers(self):
        self.assertIn("hunt-ssrf", _pattern_hits("https://example.com/go?next=/login"))

    def test_schemeless_and_bare_path_still_match(self):
        self.assertIn("hunt-auth-bypass", _pattern_hits("example.com/login"))
        self.assertIn("hunt-business-logic", _pattern_hits("/checkout"))

    def test_schemeless_host_is_not_a_path_target(self):
        # schemeless input: the host must not land in the path and fire a path rule
        self.assertNotIn("hunt-rce", _pattern_hits("api.php.net/status"))
        self.assertNotIn("hunt-aspnet", _pattern_hits("api.php.net/status"))

    def test_schemeless_path_extension_still_matches(self):
        self.assertIn("hunt-rce", _pattern_hits("example.com/upload.php"))


if __name__ == "__main__":
    unittest.main()
