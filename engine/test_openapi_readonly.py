import json
import unittest
from unittest.mock import Mock, patch

import recon
from scope import Scope


class OpenAPIReadOnlyTests(unittest.TestCase):
    def test_recon_maps_writes_but_only_probes_them_after_opt_in(self):
        spec = {
            "security": [{"session": []}],
            "paths": {"/api/items": {"get": {}, "post": {}, "delete": {}}},
        }
        scope = Scope(["example.test"], seeds=["https://example.test"])
        for intrusive, methods in ((False, ["GET"]), (True, ["GET", "POST", "DELETE"])):
            with self.subTest(intrusive=intrusive), \
                 patch.object(recon, "_probe", return_value=(200, json.dumps(spec))), \
                 patch("urllib.request.urlopen", return_value=Mock(status=401)) as request:
                items = recon.openapi_recon(scope, log=Mock(), allow_intrusive=intrusive)
                self.assertEqual({item["method"] for item in items}, {"GET", "POST", "DELETE"})
                self.assertEqual([call.args[0].get_method() for call in request.call_args_list],
                                 methods)
