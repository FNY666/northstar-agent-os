import ast
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from countdown import Countdown

class ContractTests(unittest.TestCase):
    def test_public_suite_has_coverage_without_sleep(self):
        path = Path("tests/test_countdown.py")
        source = path.read_text()
        tree = ast.parse(source)
        assertions = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"assertTrue", "assertFalse", "assertEqual", "assertRaises"}]
        self.assertGreaterEqual(len(assertions), 3)
        spec = importlib.util.spec_from_file_location("candidate_countdown_tests", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        suite = unittest.defaultTestLoader.loadTestsFromModule(module)
        self.assertGreaterEqual(suite.countTestCases(), 3)
        result = unittest.TestResult()
        with patch("time.sleep", side_effect=AssertionError("real sleep forbidden")):
            suite.run(result)
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)
        self.assertFalse(result.skipped)
        # A replacement suite must detect broken production behavior, rather
        # than becoming three unconditional passing assertions.
        for always_expired in (True, False):
            mutant_suite = unittest.defaultTestLoader.loadTestsFromModule(module)
            mutant_result = unittest.TestResult()
            with patch("countdown.Countdown.expired", return_value=always_expired):
                mutant_suite.run(mutant_result)
            self.assertFalse(mutant_result.wasSuccessful(), "tests lost timeout boundary coverage")

    def test_production_boundary_is_preserved(self):
        now = [1.0]
        timer = Countdown(2, clock=lambda: now[0])
        self.assertFalse(timer.expired())
        now[0] = 3.0
        self.assertTrue(timer.expired())
        now[0] = 4.0
        self.assertTrue(timer.expired())

if __name__ == "__main__":
    unittest.main()
