"""osint.probe must not follow redirects out of scope, and seed probing/crawling
must filter seeds against the active scope before issuing requests.
"""
from pathlib import Path
import unittest
from unittest.mock import patch

import osint
import recon
from scope import Scope


class OsintRedirectScopeTests(unittest.TestCase):
    def test_probe_never_passes_curl_dash_l(self):
        cmds = []

        def fake_run(cmd, timeout):
            cmds.append(cmd)
            Path(cmd[cmd.index("-o") + 1]).write_text("<title>ok</title>", encoding="utf-8")
            return "HTTP/1.1 200 OK\r\n"

        with patch.object(osint, "_run", side_effect=fake_run):
            res = osint.probe("app.example.com")
        self.assertEqual(res["status"], 200)
        self.assertTrue(all("-L" not in c for c in cmds), cmds)

    def test_offscope_redirect_is_not_followed(self):
        scope = Scope(["example.com"], out_of_scope=["admin.example.com"])
        requested = []

        def fake_run(cmd, timeout):
            url = cmd[-1]
            requested.append(url)
            body_path = Path(cmd[cmd.index("-o") + 1])
            if url == "https://app.example.com/":
                body_path.write_text("", encoding="utf-8")
                return "HTTP/1.1 302 Found\r\nLocation: https://admin.example.com/login\r\n"
            body_path.write_text("<title>ADMIN</title>", encoding="utf-8")
            return "HTTP/1.1 200 OK\r\n"

        with patch.object(osint, "_run", side_effect=fake_run):
            res = osint.probe("app.example.com", allow=scope.in_scope_host)
        self.assertEqual(res["status"], 302)
        self.assertEqual(requested, ["https://app.example.com/"])

    def test_inscope_relative_redirect_is_followed(self):
        scope = Scope(["example.com"])
        requested = []

        def fake_run(cmd, timeout):
            url = cmd[-1]
            requested.append(url)
            body_path = Path(cmd[cmd.index("-o") + 1])
            if url == "https://app.example.com/":
                body_path.write_text("", encoding="utf-8")
                return "HTTP/1.1 301 Moved Permanently\r\nLocation: /home\r\n"
            body_path.write_text("<title>Home</title>", encoding="utf-8")
            return "HTTP/1.1 200 OK\r\nServer: nginx\r\n"

        with patch.object(osint, "_run", side_effect=fake_run):
            res = osint.probe("app.example.com", allow=scope.in_scope_host)
        self.assertEqual(res["status"], 200)
        self.assertEqual(res["title"], "Home")
        self.assertEqual(requested, ["https://app.example.com/", "https://app.example.com/home"])

    def test_probe_hosts_drops_out_of_scope_hosts(self):
        scope = Scope(["example.com"], out_of_scope=["admin.example.com"])
        probed = []

        def fake_probe(h, allow=None):
            probed.append(h)
            return {"host": h, "url": f"https://{h}/", "status": 200, "server": "", "title": "", "tech": []}

        with patch.object(osint, "_pd_httpx", return_value=None), \
             patch.object(osint, "probe", side_effect=fake_probe):
            targets, _ = osint.probe_hosts(["app.example.com", "admin.example.com", "evil.test"], scope=scope)
        self.assertEqual(probed, ["app.example.com"])
        self.assertEqual([t["host"] for t in targets], ["app.example.com"])


class KatanaSeedScopeTests(unittest.TestCase):
    def test_katana_skips_out_of_scope_seeds(self):
        scope = Scope(["example.com"], out_of_scope=["admin.example.com"],
                      seeds=["https://app.example.com/", "https://admin.example.com/", "https://evil.test/"])
        crawled = []

        class FakeProc:
            stdout = ""

        def fake_run(cmd, **kwargs):
            crawled.append(cmd[cmd.index("-u") + 1])
            return FakeProc()

        with patch.object(recon, "which", return_value="/usr/bin/katana"), \
             patch("subprocess.run", side_effect=fake_run):
            recon._katana_urls(scope, log=lambda *a: None)
        self.assertEqual(crawled, ["https://app.example.com/"])


if __name__ == "__main__":
    unittest.main()
