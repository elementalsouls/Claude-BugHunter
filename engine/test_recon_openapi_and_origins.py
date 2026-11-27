"""Regression tests for platform_recon/openapi_recon seed origin handling
and OpenAPI Path Item metadata/null safety.
"""
import json
import unittest
from unittest.mock import Mock, patch

import recon
from scope import Scope


class ReconSeedOriginTests(unittest.TestCase):
    def test_platform_recon_preserves_non_default_port_and_strips_userinfo_and_path(self):
        scope = Scope(
            ["127.0.0.1"],
            seeds=["http://user:pass@127.0.0.1:8443/app/dashboard?tab=1"],
        )
        probed = []

        def fake_probe(url, timeout=12, allow=None):
            probed.append(url)
            return 0, ""

        with patch.object(recon, "_probe", side_effect=fake_probe):
            recon.platform_recon(scope, log=lambda *a: None)
        self.assertTrue(probed)
        self.assertTrue(
            all(u.startswith("http://127.0.0.1:8443/") for u in probed),
            probed,
        )

    def test_openapi_recon_normalizes_seed_paths_preserves_port_and_deduplicates_origins(self):
        scope = Scope(
            ["api.example.test"],
            seeds=[
                "https://api.example.test:8443/v1/login?next=/home",
                "https://api.example.test:8443/v2/users",
            ],
        )
        probed = []
        spec = {"paths": {"/health": {"get": {}}}}

        def fake_probe(url, timeout=12, allow=None):
            probed.append(url)
            if url == "https://api.example.test:8443/openapi.json":
                return 200, json.dumps(spec)
            return 0, ""

        with patch.object(recon, "_probe", side_effect=fake_probe), \
             patch.object(recon, "auth_enforcement_sweep", return_value=[]):
            items = recon.openapi_recon(scope, log=lambda *a: None)
        self.assertEqual(probed, ["https://api.example.test:8443/openapi.json"])
        self.assertEqual([it["url"] for it in items], ["https://api.example.test:8443/health"])


class OpenAPISpecSafetyTests(unittest.TestCase):
    def test_openapi_recon_and_auth_sweep_tolerate_path_metadata_and_null_fields(self):
        spec = {
            "info": None,
            "security": [{"bearer": []}],
            "paths": {
                "/users/{id}": {
                    "summary": "User resource",
                    "parameters": [{"name": "tenant", "in": "header"}],
                    "get": {
                        "parameters": [
                            {"$ref": "#/components/parameters/UserId"},
                            {"name": "id", "in": "path", "required": True},
                        ]
                    },
                    "post": None,
                },
                "/search": {
                    "GET": {"parameters": None},
                },
                "x-vendor": "ignored-non-dict",
            },
        }
        scope = Scope(["api.example.test"], seeds=["https://api.example.test"])
        seen_urls = []

        def fake_open(req, timeout=10):
            seen_urls.append(req.full_url)
            return Mock(status=401)

        with patch.object(recon, "_probe", return_value=(200, json.dumps(spec))), \
             patch.object(recon._OPENER, "open", side_effect=fake_open):
            items = recon.openapi_recon(scope, log=lambda *a: None)

        self.assertEqual({it["method"] for it in items}, {"GET"})
        self.assertIn("https://api.example.test/users/zzz-pentest-nonexistent-00000", seen_urls)
        self.assertIn("https://api.example.test/search", seen_urls)


if __name__ == "__main__":
    unittest.main()
