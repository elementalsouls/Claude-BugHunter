"""The OpenAPI auth sweep must only send requests to the spec's own host.

auth_enforcement_sweep built each URL as `base + path`, with `path` taken from
the target's spec. A key without a leading slash (`users/{id}`) or one starting
with `.` or `@` changed the authority, so unauthenticated probes went to hosts
that were never scope-checked.
"""
import unittest
from unittest.mock import Mock, patch

import recon


class AuthSweepOriginTests(unittest.TestCase):
    def test_paths_that_change_the_host_are_not_requested(self):
        spec = {
            "security": [{"bearer": []}],
            "paths": {
                "/api/items": {"get": {}},
                "users/{id}": {"get": {"parameters": [{"in": "path", "name": "id"}]}},
                ".other.example.net/x": {"get": {}},
                "@other.example.net/y": {"get": {}},
            },
        }
        with patch.object(recon._OPENER, "open", return_value=Mock(status=401)) as request, \
             patch("time.sleep"):
            recon.auth_enforcement_sweep(spec, "https://app.example.com", log=lambda _msg: None)
        sent = [call.args[0].full_url for call in request.call_args_list]
        self.assertEqual(sent, ["https://app.example.com/api/items"])


if __name__ == "__main__":
    unittest.main()
