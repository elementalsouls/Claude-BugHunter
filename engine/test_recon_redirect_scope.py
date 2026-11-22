#!/usr/bin/env python3
"""Recon must not follow redirects out of scope (#181).

Covers the one-hop, scope-gated redirect follower, spa_recon's landed-host
re-check, and (Task 7) the auth sweep grading a 3xx as enforcement.
"""
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(__file__))
import recon  # noqa: E402
from scope import Scope  # noqa: E402


class WalkTests(unittest.TestCase):
    def test_offhost_redirect_is_not_followed(self):
        hops = {
            "http://in.test/a": (302, "http://evil.test/b", ("A", "http://in.test/a", {})),
            "http://evil.test/b": (200, None, ("EVIL", "http://evil.test/b", {})),
        }
        allow = lambda u: "in.test" in u  # noqa: E731
        res = recon._walk(lambda u: hops[u], "http://in.test/a", allow)
        self.assertEqual(res[0], "A")  # stayed on the in-scope 302 response

    def test_samehost_redirect_is_followed(self):
        hops = {
            "http://in.test/": (302, "http://in.test/home", ("", "http://in.test/", {})),
            "http://in.test/home": (200, None, ("HOME", "http://in.test/home", {})),
        }
        allow = lambda u: "in.test" in u  # noqa: E731
        res = recon._walk(lambda u: hops[u], "http://in.test/", allow)
        self.assertEqual(res[0], "HOME")

    def test_none_predicate_follows_nothing(self):
        hops = {
            "http://in.test/": (302, "http://in.test/home", ("", "http://in.test/", {})),
            "http://in.test/home": (200, None, ("HOME", "http://in.test/home", {})),
        }
        res = recon._walk(lambda u: hops[u], "http://in.test/", None)
        self.assertEqual(res[0], "")  # no predicate -> do not follow


class SpaReconScopeTests(unittest.TestCase):
    def test_spa_recon_rechecks_landed_host(self):
        scope = Scope(in_scope=["in.test"], seeds=["http://in.test/"])
        calls = []

        def fake_get(url, timeout=20, allow=None):
            calls.append(url)
            if url == "http://in.test/":
                return ("<html></html>", "http://evil.test/", {})  # pretend it landed off-host
            return ("", url, {})

        with patch.object(recon, "_get", fake_get):
            recon.spa_recon(scope, log=lambda *a, **k: None)
        self.assertFalse(any("evil.test" in c for c in calls),
                         "spa_recon fetched an off-host URL: %r" % calls)


class _RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/a":
            self.send_response(302)
            self.send_header("Location", "http://evil.test/b")
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"BEE")

    def log_message(self, *a):
        pass


class _AuthRedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/login"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"login page")
        else:                                   # a secured op redirects to login = enforced
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()

    def log_message(self, *a):
        pass


class AuthSweepRedirectTests(unittest.TestCase):
    def setUp(self):
        self.srv = HTTPServer(("127.0.0.1", 0), _AuthRedirectHandler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_302_to_login_is_enforcement_not_bypass(self):
        spec = {"security": [{"s": []}], "paths": {"/secure": {"get": {}}}}
        broken = recon.auth_enforcement_sweep(spec, self.base, log=lambda *a, **k: None)
        self.assertEqual(broken, [], "a 302 to /login was graded as broken auth")


class _RedirectingParamHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/r/"):                 # the followed destination
            self.send_response(200)
            self.end_headers()
            q = self.path.split("?", 1)
            body = b"BASE" + (("?" + q[1]).encode() if len(q) > 1 else b"")  # echo the param
            self.wfile.write(body)
        else:                                           # /r or /r?... -> 301 keeping the query
            q = self.path.split("?", 1)
            self.send_response(301)
            self.send_header("Location", "/r/" + ("?" + q[1] if len(q) > 1 else ""))
            self.end_headers()

    def log_message(self, *a):
        pass


class PruneRedirectTests(unittest.TestCase):
    def setUp(self):
        self.srv = HTTPServer(("127.0.0.1", 0), _RedirectingParamHandler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    @unittest.skipUnless(__import__("shutil").which("curl"), "curl required")
    def test_prune_keeps_live_param_behind_in_scope_redirect(self):
        scope = Scope(in_scope=["127.0.0.1"])
        items = [{"url": self.base + "/r?p=FUZZ", "param": "p", "method": "GET", "source": "x"}]
        kept = recon.prune_inert_params(items, log=lambda *a, **k: None, scope=scope)
        self.assertEqual(len(kept), 1, "a live param behind an in-scope redirect was pruned")


class OpenerNoRedirectTests(unittest.TestCase):
    def setUp(self):
        self.srv = HTTPServer(("127.0.0.1", 0), _RedirectHandler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_module_opener_does_not_follow_redirects(self):
        import urllib.error
        with self.assertRaises(urllib.error.HTTPError) as cm:
            recon._OPENER.open("http://127.0.0.1:%d/a" % self.port, timeout=5)
        self.assertEqual(cm.exception.code, 302)  # 3xx surfaced, not followed


if __name__ == "__main__":
    unittest.main()
