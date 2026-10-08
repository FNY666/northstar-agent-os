"""Behavioral controls for the scoped native-pytest runner, using real child runs."""
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

RUNNER = Path(__file__).resolve().parents[1] / "run_runtime_pytest.py"


class NativePytestRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="native pytest controls ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, source):
        (self.root / name).write_text(source, encoding="utf-8")

    def run_suite(self):
        self.assertTrue(RUNNER.is_file(), "native pytest runner is missing")
        env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
        result = subprocess.run(
            [sys.executable, str(RUNNER), "-q", str(self.root)],
            cwd=self.root, env=env, text=True, capture_output=True, timeout=40,
        )
        result.output = result.stdout + result.stderr
        return result

    def assert_passed(self, result, count):
        self.assertEqual(result.returncode, 0, result.output)
        self.assertIn(f"{count} passed", result.output)

    def test_import_free_function_is_executed(self):
        marker = self.root / "function-ran"
        self.write("test_function.py", f"from pathlib import Path\ndef test_function():\n    Path({str(marker)!r}).write_text('ran')\n")
        self.assert_passed(self.run_suite(), 1)
        self.assertEqual(marker.read_text(), "ran")

    def test_import_free_plain_class_is_executed(self):
        self.write("test_class.py", "class TestPlain:\n    def test_method(self):\n        assert 1 + 1 == 2\n")
        self.assert_passed(self.run_suite(), 1)

    def test_native_fixtures_and_parameterization_are_preserved(self):
        self.write("test_params.py", "import pytest\n@pytest.fixture\ndef number():\n    return 7\n@pytest.mark.parametrize('value', [1, 2, 3])\ndef test_parameter(value, number):\n    assert number == 7 and value > 0\n")
        self.assert_passed(self.run_suite(), 3)

    def test_indirect_testcase_inheritance_is_not_double_run(self):
        marker = self.root / "unittest-ran"
        self.write("test_inheritance.py", f"import unittest\nfrom pathlib import Path\nclass Base(unittest.TestCase):\n    def test_reserved_for_unittest(self):\n        Path({str(marker)!r}).write_text('duplicate')\n        self.fail('must not run in pytest lane')\nclass TestInherited(Base):\n    pass\ndef test_native():\n    assert True\n")
        self.assert_passed(self.run_suite(), 1)
        self.assertFalse(marker.exists(), "TestCase ran in both lanes")

    def test_new_file_is_discovered_without_list_updates(self):
        self.write("test_first.py", "def test_first():\n    assert True\n")
        self.assert_passed(self.run_suite(), 1)
        self.write("test_later.py", "def test_later():\n    assert True\n")
        self.assert_passed(self.run_suite(), 2)

    def test_real_test_failure_propagates_nonzero(self):
        self.write("test_failure.py", "def test_failure():\n    assert False, 'real failure sentinel'\n")
        result = self.run_suite()
        self.assertEqual(result.returncode, 1, result.output)
        self.assertIn("real failure sentinel", result.output)
        self.assertIn("1 failed", result.output)

    def test_syntax_collection_error_does_not_block_valid_test(self):
        marker = self.root / "valid-ran"
        self.write("test_broken.py", "def test_broken(:\n    pass\n")
        self.write("test_valid.py", f"from pathlib import Path\ndef test_valid():\n    Path({str(marker)!r}).write_text('ran')\n")
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.output)
        self.assertIn("SyntaxError", result.output)
        self.assertIn("1 passed", result.output)
        self.assertEqual(marker.read_text(), "ran")

    def test_import_collection_error_is_not_swallowed(self):
        self.write("test_missing.py", "import nonexistent_native_runner_fixture_dependency\n")
        self.write("test_valid.py", "def test_valid():\n    assert True\n")
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0, result.output)
        self.assertIn("ModuleNotFoundError", result.output)
        self.assertIn("1 passed", result.output)
        self.assertIn("1 error", result.output)

    def test_only_testcase_is_zero_native_tests_not_success(self):
        self.write("test_unit.py", "import unittest\nclass TestUnit(unittest.TestCase):\n    def test_one(self):\n        self.fail('pytest must not execute this')\n")
        result = self.run_suite()
        self.assertEqual(result.returncode, 5, result.output)
        self.assertIn("no tests ran", result.output)

    def test_testimonial_domain_function_is_not_a_test(self):
        # Actual runtime modules export testimonial_existence_gate. Pytest's
        # broad default 'test' prefix mistakes it for a fixture-taking test.
        self.write("domain_helper.py", "def testimonial_existence_gate(persona_kind):\n    raise AssertionError('domain function is not a test')\n")
        self.write("test_domain.py", "from domain_helper import testimonial_existence_gate\ndef test_real():\n    assert True\n")
        self.assert_passed(self.run_suite(), 1)

    def test_mixed_module_keeps_native_items_only(self):
        self.write("test_mixed.py", "import unittest\nclass TestUnit(unittest.TestCase):\n    def test_unittest(self):\n        self.fail('duplicate')\nclass TestNative:\n    def test_method(self):\n        assert True\ndef test_function():\n    assert True\n")
        self.assert_passed(self.run_suite(), 2)


if __name__ == "__main__":
    unittest.main()
