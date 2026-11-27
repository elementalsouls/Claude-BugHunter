"""Producers must not emit a URL whose authority was set by untrusted input.

#263: auth_enforcement_sweep / openapi_recon build `base + path` where `path` is
a key from the target-served spec. A path key without a leading `/`
(`users/{id}`) or starting with `.`/`@` changes the URL's netloc, so the engine
sends unauthenticated requests to a host that was never scope-checked. Any path
whose joined netloc differs from the base's must be skipped.

#261: platform_recon appends OIDC authorization/token/registration endpoints
from a discovery document with no scope check, so a third-party IdP lands in the
surface/arsenal as an oauth target. Only in-scope endpoints may be added.
"""
import unittest
from unittest import mock

import recon
from scope import Scope


class AuthSweepAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.sent = []

        class FakeResp:
            status = 200

        def fake_open(req, timeout=10):
            self.sent.append(req.full_url)
            return FakeResp()

        self.patch = mock.patch.object(recon._OPENER, "open", side_effect=fake_open)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def _spec(self, *paths):
        return {"security": [{"x": []}],
                "paths": {p: {"get": {"security": [{"x": []}]}} for p in paths}}

    def test_only_same_authority_paths_are_requested(self):
        spec = self._spec("/ok", "users/zzz", ".attacker.example/x", "@other.example/y")
        recon.auth_enforcement_sweep(spec, "https://app.example.com", log=lambda *a: None)
        for url in self.sent:
            self.assertTrue(
                url.startswith("https://app.example.com/"),
                f"request escaped base authority: {url}")
        self.assertIn("https://app.example.com/ok", self.sent)
        self.assertEqual(len(self.sent), 1)


class OpenapiAuthorityTests(unittest.TestCase):
    def test_openapi_items_stay_on_base_host(self):
        scope = Scope(["app.example.com"], seeds=["https://app.example.com"])
        spec = {"paths": {"/good": {"get": {}}, "users/{id}": {"get": {}},
                          "@evil.example/x": {"get": {}}}}

        def fake_probe(url, allow=None):
            if url.endswith("/openapi.json"):
                import json
                return 200, json.dumps(spec)
            return 0, ""

        with mock.patch.object(recon, "_probe", side_effect=fake_probe), \
             mock.patch.object(recon, "auth_enforcement_sweep", return_value=[]):
            items = recon.openapi_recon(scope, log=lambda *a: None)
        for it in items:
            self.assertTrue(it["url"].startswith("https://app.example.com/"),
                            f"surface item escaped base host: {it['url']}")
        self.assertTrue(any(it["url"] == "https://app.example.com/good" for it in items))


class PlatformReconOidcScopeTests(unittest.TestCase):
    def test_offscope_oidc_endpoints_not_added(self):
        scope = Scope(["app.example.com"], seeds=["https://app.example.com"])
        disco = {
            "issuer": "https://app.example.com",
            "authorization_endpoint": "https://app.example.com/oauth/authorize",
            "token_endpoint": "https://tenant.idp-vendor.example.net/oauth/token",
            "registration_endpoint": "https://app.example.com/oauth/register",
        }

        def fake_probe(url, allow=None):
            if url.endswith("/.well-known/openid-configuration"):
                import json
                return 200, json.dumps(disco)
            return 0, ""

        with mock.patch.object(recon, "_probe", side_effect=fake_probe):
            items = recon.platform_recon(scope, log=lambda *a: None)
        oauth = [it["url"] for it in items if it.get("vuln_class") == "oauth"]
        self.assertIn("https://app.example.com/oauth/authorize", oauth)
        self.assertIn("https://app.example.com/oauth/register", oauth)
        self.assertNotIn("https://tenant.idp-vendor.example.net/oauth/token", oauth)


if __name__ == "__main__":
    unittest.main()
