"""Recon must never follow a redirect off scope.

The engine runs unattended: an in-scope seed that 302s to an SSO provider, a
deny-listed admin host or a third party must not cause recon to request that
destination (or its /robots.txt and /sitemap.xml).
"""
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from shutil import which
from unittest.mock import patch

import recon
from scope import Scope

SCOPE = Scope(["app.example.test"], ["admin.app.example.test"],
              seeds=["https://app.example.test/"])


class FakeWeb:
    """url -> (status, body, location); records every URL actually requested."""

    def __init__(self, routes):
        self.routes, self.requested = routes, []

    def __call__(self, url, timeout=20):
        self.requested.append(url)
        status, body, location = self.routes.get(url, (404, "", ""))
        return status, body, ({"location": location} if location else {}), location

    def hosts(self):
        from urllib.parse import urlparse
        return {urlparse(u).hostname for u in self.requested}


class SpaReconRedirectTests(unittest.TestCase):
    def test_redirect_to_out_of_scope_host_is_not_followed(self):
        web = FakeWeb({
            "https://app.example.test/": (302, "", "https://login.thirdparty.test/sso?next=/"),
            "https://login.thirdparty.test/sso?next=/": (200, '<script src="/app.js"></script>', ""),
        })
        with patch.object(recon, "_get_once", web):
            recon.spa_recon(SCOPE, log=lambda *_: None)
        self.assertEqual(web.hosts(), {"app.example.test"})
        # robots/sitemap are requested against the in-scope origin, not the redirect target
        self.assertIn("https://app.example.test/robots.txt", web.requested)

    def test_redirect_to_deny_listed_subdomain_is_not_followed(self):
        web = FakeWeb({"https://app.example.test/": (301, "", "https://admin.app.example.test/")})
        with patch.object(recon, "_get_once", web):
            recon.spa_recon(SCOPE, log=lambda *_: None)
        self.assertNotIn("admin.app.example.test", web.hosts())

    def test_in_scope_redirect_is_still_followed(self):
        web = FakeWeb({
            "https://app.example.test/": (302, "", "/home"),
            "https://app.example.test/home": (200, 'fetch("/api/v1/users")', ""),
        })
        with patch.object(recon, "_get_once", web):
            items, _ = recon.spa_recon(SCOPE, log=lambda *_: None)
        self.assertIn("https://app.example.test/home", web.requested)
        self.assertIn("https://app.example.test/api/v1/users", [i["url"] for i in items])

    def test_redirect_chain_is_bounded(self):
        web = FakeWeb({"https://app.example.test/": (302, "", "/")})
        with patch.object(recon, "_get_once", web):
            recon._get("https://app.example.test/", allow=SCOPE.in_scope_host)
        self.assertEqual(len(web.requested), recon.MAX_REDIRECTS + 1)


class ProbeRedirectTests(unittest.TestCase):
    def test_platform_recon_probes_stay_in_scope(self):
        routes = {f"https://app.example.test{wk}": (302, "", "https://cdn.thirdparty.test" + wk)
                  for wk in recon.WELLKNOWN}
        web = FakeWeb(routes)
        with patch.object(recon, "_curl_once", web):
            recon.platform_recon(SCOPE, log=lambda *_: None)
        self.assertEqual(web.hosts(), {"app.example.test"})

    def test_out_of_scope_seed_is_never_probed(self):
        web = FakeWeb({})
        scope = Scope(["app.example.test"], seeds=["https://other.test/"])
        with patch.object(recon, "_curl_once", web):
            recon.platform_recon(scope, log=lambda *_: None)
            recon.openapi_recon(scope, log=lambda *_: None)
        self.assertEqual(web.requested, [])

    def test_prune_follows_nothing_without_a_scope_predicate(self):
        web = FakeWeb({"https://app.example.test/x": (302, "", "https://elsewhere.test/")})
        with patch.object(recon, "_curl_once", web):
            recon.prune_inert_params([{"url": "https://app.example.test/x?q=FUZZ", "param": "q"}],
                                     log=lambda *_: None)
        self.assertNotIn("elsewhere.test", web.hosts())


class _Server:
    """A real loopback server: /start -> 302 /dest, /api/secure -> 302 /login."""

    def __enter__(self):
        self.paths = []
        paths = self.paths

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                paths.append(self.path)
                target = {"/start": "/dest", "/api/secure": "/login"}.get(self.path)
                self.send_response(302 if target else 200)
                if target:
                    self.send_header("Location", target)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.env = patch.dict(os.environ, {"no_proxy": "127.0.0.1", "NO_PROXY": "127.0.0.1"})
        self.env.start()
        return self

    def __exit__(self, *exc):
        self.env.stop()
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()


class RealTransportTests(unittest.TestCase):
    def test_stdlib_backend_does_not_follow_on_its_own(self):
        with _Server() as srv:
            status, _, _, final = recon._follow(recon._get_once_urllib, srv.base + "/start", 5, None)
            self.assertEqual((status, final), (302, srv.base + "/start"))
            status, body, _, final = recon._follow(recon._get_once_urllib, srv.base + "/start", 5,
                                                   lambda _u: True)
            self.assertEqual((status, body, final), (200, "ok", srv.base + "/dest"))
        self.assertEqual(srv.paths, ["/start", "/start", "/dest"])

    @unittest.skipUnless(which("curl"), "curl not installed")
    def test_curl_backend_does_not_follow_on_its_own(self):
        with _Server() as srv:
            self.assertEqual(recon._probe(srv.base + "/start")[0], 302)
            status, body = recon._probe(srv.base + "/start", allow=lambda _u: True)
            self.assertEqual((status, body.strip()), (200, "ok"))
        self.assertEqual(srv.paths, ["/start", "/start", "/dest"])

    def test_auth_sweep_treats_login_redirect_as_enforced(self):
        spec = {"security": [{"bearer": []}], "paths": {"/api/secure": {"get": {}}}}
        with _Server() as srv:
            broken = recon.auth_enforcement_sweep(spec, srv.base, log=lambda *_: None)
        self.assertEqual(broken, [])               # was "200 UNAUTH" via the followed login page
        self.assertEqual(srv.paths, ["/api/secure"])


if __name__ == "__main__":
    unittest.main()
