"""Subdomain-enumeration roots must come from the authorized scope, not from
truncating a seed host to its last two labels. Under a multi-label public suffix
(`example.co.uk`, `*.com.au`) that truncation lands on the suffix itself (`co.uk`),
so enumeration queries the whole suffix and `--expand` never enumerates the target.
Reported in #213."""
import unittest

import osint
from scope import Scope


class EnumerationRootTests(unittest.TestCase):
    def test_roots_follow_authorized_domains(self):
        cases = [
            # multi-label suffix: root stays the real domain, not co.uk
            (["*.example.co.uk"], ["https://example.co.uk"], ["example.co.uk"]),
            (["*.example.com"], ["https://api.example.com"], ["example.com"]),
            # exact-host scope with no wildcard: root is that host
            (["app.example.com"], ["https://app.example.com"], ["app.example.com"]),
            # IP literals produce no enumeration root
            (["127.0.0.1", "::1"], ["http://127.0.0.1", "http://[::1]"], []),
            # regex rules are not roots; path/port forms are normalized to the host
            # by the scope gate (#205), so they DO contribute example.com as a root
            (["re:.*example.com", "example.com/path", "example.com:8080"], [], ["example.com"]),
            # seed nothing covers → full hostname, lowercased, trailing dot stripped
            ([], ["https://App.Example.COM./"], ["app.example.com"]),
            # seed covered by two domains → shortest covering root plus both domains
            (["*.EXAMPLE.COM.", "api.example.com"], ["https://v1.api.example.com"],
             ["api.example.com", "example.com"]),
            ([], [], []),
            ([], ["http://[invalid"], []),
        ]
        for patterns, seeds, expected in cases:
            with self.subTest(patterns=patterns, seeds=seeds):
                self.assertEqual(osint.enumeration_roots(Scope(patterns, seeds=seeds)), expected)


if __name__ == "__main__":
    unittest.main()
