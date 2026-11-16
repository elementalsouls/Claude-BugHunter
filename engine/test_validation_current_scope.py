import tempfile
import unittest
from unittest.mock import Mock

from engine import Engine
from scope import Scope
from state import Engagement


class ValidationCurrentScopeTests(unittest.TestCase):
    def test_resumed_validation_uses_current_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            engagement = Engagement(folder, "synthetic")
            removed = {"url": "https://removed.example.test/", "vuln_class": "cors"}
            active = {"url": "https://active.example.test/", "vuln_class": "cors"}
            engagement.add_candidate(removed)
            engagement.add_candidate(active)
            runner = Engine.__new__(Engine)
            runner.eng = Engagement(folder, "synthetic")
            runner.scope = Scope(["example.test"], ["removed.example.test"])
            runner.parallel = 1
            runner._validate_agent = Mock(return_value={"real": False, "reason": "synthetic"})
            runner.validate()
            runner._validate_agent.assert_called_once_with(active)
