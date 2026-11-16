from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from unittest import TestCase
from unittest.mock import patch

import osint


class ProbeBodyTests(TestCase):
    def test_concurrent_fingerprints_use_their_own_response_body(self):
        barrier = Barrier(2)
        paths = []

        def curl(command, timeout):
            body = Path(command[command.index("-o") + 1])
            paths.append(body)
            title = command[-1].split("/")[2]
            body.write_text(f"<title>{title}</title>", encoding="utf-8")
            barrier.wait(timeout=5)
            return "HTTP/1.1 200 OK\r\n"

        hosts = ["one.example.test", "two.example.test"]
        with patch.object(osint, "_run", side_effect=curl), ThreadPoolExecutor(2) as pool:
            results = list(pool.map(osint.probe, hosts))
        self.assertEqual([result["title"] for result in results], hosts)
        self.assertEqual(len(set(paths)), 2)
        self.assertTrue(all(not path.exists() for path in paths))
