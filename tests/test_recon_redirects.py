import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from cbh import cli


class ReconRedirectTests(unittest.TestCase):
    def test_first_hop_is_recorded_and_redirect_target_is_never_requested(self):
        requests = []

        class RedirectingHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                if self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", "/destination")
                else:
                    self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        with HTTPServer(("127.0.0.1", 0), RedirectingHandler) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            url = f"http://127.0.0.1:{server.server_port}/start"
            try:
                with patch.dict(os.environ, {"no_proxy": "127.0.0.1"}):
                    with patch.object(cli, "_HTTP_OPENER", None):
                        code, headers, _ = cli.http_get(url, follow_redirects=False)
                        self.assertEqual(code, 302)
                        self.assertEqual(headers["Location"], "/destination")

                        # Proxy configuration must preserve the same behavior.
                        cli.configure_http_proxy("http://127.0.0.1:1")
                        self.assertEqual(cli.http_get(url, follow_redirects=False)[0], 302)
                        self.assertEqual(cli.http_get(url)[0], 200)
            finally:
                server.shutdown()
                thread.join()
        self.assertEqual(requests, ["/start", "/start", "/start", "/destination"])
