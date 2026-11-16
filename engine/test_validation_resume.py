import tempfile
import unittest
from unittest.mock import Mock

import engine
from scope import Scope
from state import Engagement


class ValidationResumeTests(unittest.TestCase):
    def test_confirmed_parameter_does_not_hide_other_parameters(self):
        with tempfile.TemporaryDirectory() as base:
            engagement = Engagement(base, "synthetic")
            first = {"url": "https://example.test/items?a=1&b=2", "vuln_class": "xss", "param": "a"}
            second = {**first, "param": "b"}
            engagement.add_candidate(first)
            engagement.add_candidate(second)
            engagement.confirm(first, {"real": True})

            runner = engine.Engine.__new__(engine.Engine)
            runner.eng = Engagement(base, "synthetic")
            runner.scope = Scope(["example.test"])
            runner.parallel = 1
            runner._validate_agent = Mock(return_value={"real": False, "reason": "synthetic"})
            runner.validate()

            runner._validate_agent.assert_called_once_with(second)

    def test_resume_retries_inconclusive_but_not_rejected_candidates(self):
        with tempfile.TemporaryDirectory() as base:
            runner = engine.Engine.__new__(engine.Engine)
            runner.eng = Engagement(base, "synthetic")
            rejected = {"url": "https://example.test/a", "vuln_class": "xss"}
            inconclusive = {**rejected, "url": "https://example.test/b"}
            runner.eng.add_candidate(rejected)
            runner.eng.add_candidate(inconclusive)
            runner.scope = Scope(["example.test"])
            runner.parallel = 1
            runner._validate_agent = Mock(side_effect=[
                {"real": False, "reason": "unexploitable"},
                {"real": False, "errored": True, "reason": "timeout"},
            ])
            runner.validate()

            runner.eng = Engagement(base, "synthetic")
            runner._validate_agent = Mock(return_value={"errored": True})
            runner.validate()

            runner._validate_agent.assert_called_once_with(inconclusive)
