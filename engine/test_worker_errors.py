import unittest
from types import SimpleNamespace
from unittest.mock import Mock

import engine


class WorkerErrorTests(unittest.TestCase):
    def test_single_worker_failure_does_not_abort_later_items(self):
        runner = engine.Engine.__new__(engine.Engine)
        runner.parallel = 1
        runner.eng = SimpleNamespace(log=Mock())
        items = [{"url": "https://a.example.test/"}, {"url": "https://b.example.test/"}]
        worker = Mock(side_effect=[RuntimeError("synthetic failure"), {"vulnerable": False}])
        self.assertEqual(list(runner._run_parallel(worker, items)),
                         [(items[0], {}), (items[1], {"vulnerable": False})])

    def test_single_item_uses_same_error_handling_as_a_batch(self):
        runner = engine.Engine.__new__(engine.Engine)
        runner.parallel = 3
        runner.eng = SimpleNamespace(log=Mock())
        item = {"url": "https://example.test/"}
        worker = Mock(side_effect=RuntimeError("synthetic failure"))
        self.assertEqual(list(runner._run_parallel(worker, [item])), [(item, {})])
