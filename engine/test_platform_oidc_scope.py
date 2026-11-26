"""OIDC discovery endpoints that live on another host must not become surface.

platform_recon added authorization/token/registration endpoints from
/.well-known/openid-configuration without a scope check, so a third-party IdP
showed up in arsenal.md as an `oauth` target with a ready-made curl probe.
"""
import json
import unittest
from unittest.mock import patch

import recon
from scope import Scope


class PlatformOIDCScopeTests(unittest.TestCase):
    def test_only_in_scope_oauth_endpoints_are_added(self):
        meta = {
            "issuer": "https://login.example.com/",
            "authorization_endpoint": "https://login.example.com/authorize",
            "token_endpoint": "https://tenant.idp.example.net/oauth/token",
            "registration_endpoint": "https://tenant.idp.example.net/register",
        }
        scope = Scope(["example.com"], seeds=["https://app.example.com"])

        def probe(url, timeout=12, allow=None):
            if url.endswith("/.well-known/openid-configuration"):
                return 200, json.dumps(meta)
            return 404, ""

        with patch.object(recon, "_probe", side_effect=probe):
            items = recon.platform_recon(scope, log=lambda _msg: None)
        urls = [item["url"] for item in items]
        self.assertIn("https://login.example.com/authorize", urls)
        self.assertNotIn("https://tenant.idp.example.net/oauth/token", urls)
        self.assertNotIn("https://tenant.idp.example.net/register", urls)
        self.assertTrue(all(scope.in_scope_host(url) for url in urls), urls)


if __name__ == "__main__":
    unittest.main()
