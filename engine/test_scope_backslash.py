"""Scope bypass via backslash/control chars in the URL authority (parser
differential, privately reported).

`_host_of` used urlparse, which treats `\\` as a normal character, while
requests/urllib3 (and browsers) treat it as `/` in the authority. So
`http://admin.example.com\\@www.example.com/` parses as host `www.example.com`
(in scope) but the request actually connects to `admin.example.com` (out of
scope). The gate must FAIL CLOSED on any authority that two parsers can read
differently — a backslash, whitespace, or control char in the netloc — while
leaving path/query backslashes (Windows LFI `?file=..\\..\\win.ini`) in scope.
"""
import unittest

from scope import Scope, _host_of


class BackslashAuthorityTests(unittest.TestCase):
    def test_backslash_authority_fails_closed(self):
        # every one of these makes urlparse and urllib3 disagree on the host
        for url in (
            r"http://admin.example.com\@www.example.com/",
            r"http://127.0.0.1:8080\@app.example.com/x",
            r"http://www.example.com\\@admin.example.com/",
            r"http://evil.com\.good.com/",
            "http://good.com @evil.com/",          # space in authority
        ):
            with self.subTest(url=url):
                self.assertEqual(_host_of(url), "", f"ambiguous authority not failed closed: {url}")

    def test_reported_bypass_is_blocked(self):
        # the exact scenario from the report: in *.example.com, deny admin.example.com
        s = Scope(in_scope=["*.example.com"], out_of_scope=["admin.example.com"])
        bypass = r"http://admin.example.com\@www.example.com/"
        self.assertFalse(s.in_scope_host(bypass))
        self.assertIsNotNone(s.reject_reason(bypass))

    def test_legitimate_urls_still_resolve(self):
        self.assertEqual(_host_of("https://api.example.com:8443/login"), "api.example.com")
        self.assertEqual(_host_of("http://[::1]:8080/x"), "::1")            # IPv6, not a bypass
        self.assertEqual(_host_of("https://user:pass@real.example.com/"), "real.example.com")
        self.assertEqual(_host_of("https://xn--80ak6aa92e.com/"), "xn--80ak6aa92e.com")

    def test_query_or_path_backslash_stays_in_scope(self):
        # Windows LFI payload — backslash is in the query, not the authority
        s = Scope(in_scope=["*.example.com"])
        url = r"http://app.example.com/download?file=..\..\win.ini"
        self.assertEqual(_host_of(url), "app.example.com")
        self.assertTrue(s.in_scope_host(url))


if __name__ == "__main__":
    unittest.main()
