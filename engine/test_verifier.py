"""Deterministic, LLM-free evidence capture + corroboration.

Hard guarantees under test:
  - capture stores a redacted, truncated real exchange; never a full dump.
  - corroborate is EVIDENCE, not a gate: it never calls confirm(), never sets
    severity, never changes the `confirmed` set. It only adds a tag.
  - XSS is tagged reflected-unencoded, never "xss confirmed".
  - Only clean idempotent GETs are replayed; a non-GET request is never re-issued.
  - Scope + read-only hold on replay.
  - Uncovered classes pass through as n/a with no demotion.
"""
import unittest
import verifier


class _Scope:
    """Minimal scope stub: deny-wins allowlist by host substring."""
    def __init__(self, allow=("target.test",), deny=()):
        self.allow, self.deny = allow, deny

    def reject_reason(self, url):
        from urllib.parse import urlparse
        host = (urlparse(url if "://" in url else "//" + url).hostname or "")
        if any(d in host for d in self.deny):
            return f"{host} out of scope (deny)"
        if any(a in host for a in self.allow):
            return None
        return f"{host} matches no in-scope rule"

    def in_scope_host(self, url):
        return self.reject_reason(url) is None


class _Fetch:
    """Records every request; returns a canned (status, headers, location, body)."""
    def __init__(self, table):
        self.table = table        # url -> (status, headers, location, body)
        self.calls = []           # list of (method, url)

    def __call__(self, url, method="GET"):
        self.calls.append((method, url))
        return self.table.get(url, (0, {}, None, ""))


class CaptureTests(unittest.TestCase):
    def test_capture_stores_redacted_truncated_exchange(self):
        body = ("<html>root:x:0:0 token=AKIAIOSFODNN7EXAMPLE "
                "mail=victim@acme.com " + "A" * 5000 + "</html>")
        fetch = _Fetch({"http://target.test/f?x=../../etc/passwd":
                        (200, {"Set-Cookie": "sid=supersecret", "X-Trace-Id": "keepme"},
                         None, body)})
        f = {"vuln_class": "lfi", "url": "http://target.test/f?x=1",
             "request": "GET /f?x=../../etc/passwd"}
        verifier.capture_exchange(f, fetch, _Scope(), max_body=512)
        ex = f["exchange"]
        self.assertEqual(ex["status"], 200)
        self.assertEqual(ex["request_line"], "GET /f?x=../../etc/passwd")
        self.assertTrue(ex["truncated"])
        self.assertLessEqual(len(ex["body_excerpt"]), 512)
        # secrets / PII redacted, triager-useful trace id kept, cookie header masked
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", ex["body_excerpt"])
        self.assertNotIn("victim@acme.com", ex["body_excerpt"])
        self.assertEqual(ex["response_headers"].get("Set-Cookie"), "[REDACTED]")
        self.assertEqual(ex["response_headers"].get("X-Trace-Id"), "keepme")

    def test_capture_refuses_out_of_scope_no_packet(self):
        fetch = _Fetch({})
        f = {"vuln_class": "lfi", "url": "http://evil.test/f",
             "request": "GET /f?x=../../etc/passwd"}
        verifier.capture_exchange(f, fetch, _Scope(deny=("evil.test",)))
        self.assertEqual(fetch.calls, [])                 # never sent
        self.assertEqual(f.get("exchange", {}).get("skipped"), "out-of-scope")

    def test_capture_only_issues_GET(self):
        fetch = _Fetch({"http://target.test/d": (200, {}, None, "ok")})
        f = {"vuln_class": "idor", "url": "http://target.test/d",
             "request": "DELETE /d/5"}
        verifier.capture_exchange(f, fetch, _Scope())
        # a non-GET winning request is never re-issued; no DELETE anywhere
        self.assertNotIn("DELETE", [m for m, _ in fetch.calls])


class CorroborateTests(unittest.TestCase):
    def _cap(self, vuln_class, request, table, url="http://target.test/x"):
        f = {"vuln_class": vuln_class, "url": url, "request": request}
        verifier.capture_exchange(f, _Fetch(table), _Scope())
        verifier.corroborate(f)
        return f

    def test_lfi_confirmed(self):
        f = self._cap("lfi", "GET /x?f=../../etc/passwd",
                      {"http://target.test/x?f=../../etc/passwd":
                       (200, {}, None, "root:x:0:0:root:/root:/bin/bash\n")})
        self.assertEqual(f["corroboration"], "confirmed")

    def test_lfi_lookalike_failed(self):
        f = self._cap("lfi", "GET /x?f=../../etc/passwd",
                      {"http://target.test/x?f=../../etc/passwd":
                       (200, {}, None, "Error: file not found (root privileges required)")})
        self.assertEqual(f["corroboration"], "failed")

    def test_sqli_confirmed(self):
        f = self._cap("sqli", "GET /x?id=1'",
                      {"http://target.test/x?id=1'":
                       (500, {}, None, "You have an error in your SQL syntax near ''' at line 1")})
        self.assertEqual(f["corroboration"], "confirmed")

    def test_sqli_generic_500_failed(self):
        f = self._cap("sqli", "GET /x?id=1'",
                      {"http://target.test/x?id=1'":
                       (500, {}, None, "Internal Server Error")})
        self.assertEqual(f["corroboration"], "failed")

    def test_open_redirect_confirmed_on_location_host(self):
        f = self._cap("open-redirect", "GET /x?next=//evil.example/",
                      {"http://target.test/x?next=//evil.example/":
                       (302, {"Location": "//evil.example/"}, "//evil.example/", "")})
        self.assertEqual(f["corroboration"], "confirmed")
        self.assertIn("evil.example", f["corroboration_signal"])

    def test_open_redirect_benign_failed(self):
        f = self._cap("open-redirect", "GET /x?next=//evil.example/",
                      {"http://target.test/x?next=//evil.example/":
                       (302, {"Location": "/dashboard"}, "/dashboard", "")})
        self.assertEqual(f["corroboration"], "failed")

    def test_xss_reflected_unencoded_confirmed_but_never_says_xss_confirmed(self):
        f = self._cap("xss", "GET /x?q=<script>cbh1</script>",
                      {"http://target.test/x?q=<script>cbh1</script>":
                       (200, {}, None, "hi <script>cbh1</script> bye")})
        self.assertEqual(f["corroboration"], "confirmed")
        self.assertIn("reflected-unencoded", f["corroboration_signal"])
        self.assertNotIn("xss confirmed", f["corroboration_signal"].lower())

    def test_xss_entity_encoded_failed(self):
        f = self._cap("xss", "GET /x?q=<script>cbh1</script>",
                      {"http://target.test/x?q=<script>cbh1</script>":
                       (200, {}, None, "hi &lt;script&gt;cbh1&lt;/script&gt; bye")})
        self.assertEqual(f["corroboration"], "failed")

    def test_uncovered_class_is_na_and_not_demoted(self):
        f = self._cap("idor", "GET /account?id=6",
                      {"http://target.test/account?id=6": (200, {}, None, "other user data")})
        self.assertEqual(f["corroboration"], "n/a")
        # corroborate must not inject a promotion signal
        self.assertNotIn("verdict", f)
        self.assertNotIn("confirmed_ts", f)

    def test_non_get_request_is_na(self):
        f = self._cap("sqli", "POST /x", {})
        self.assertEqual(f["corroboration"], "n/a")

    def test_corroborate_is_pure_no_confirm_side_effects(self):
        # a dict that looks like a state object must be untouched beyond the two tags
        f = {"vuln_class": "idor", "url": "http://target.test/x", "request": "GET /x",
             "severity": "high"}
        verifier.capture_exchange(f, _Fetch({"http://target.test/x": (200, {}, None, "ok")}), _Scope())
        before = f.get("severity")
        verifier.corroborate(f)
        self.assertEqual(f["severity"], before)            # severity untouched
        self.assertIn("corroboration", f)


if __name__ == "__main__":
    unittest.main()
