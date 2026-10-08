"""Tests for dx_21. test runners."""
import importlib.util, sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent

def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m

dx = _load("dx_21")

def _runner():
    r = dx.TestRunner()
    r.register_suite("unit", [
        dx.TestCase("test_a", "pass"),
        dx.TestCase("test_b", "fail"),
        dx.TestCase("test_c", "skip"),
        dx.TestCase("db_test", "pass"),
    ])
    return r


def test_run_summary():
    s = _runner().run("unit")
    assert (s.passed, s.failed, s.skipped, s.total) == (2, 1, 1, 4)
    assert s.failures == ["test_b"]


def test_prefix_filter():
    s = _runner().run("unit", prefix="test_")
    assert s.total == 3 and s.passed == 1


def test_unknown_suite_raises():
    with pytest.raises(dx.TestRunError):
        _runner().run("nope")


def test_bad_outcome_raises():
    r = dx.TestRunner()
    with pytest.raises(dx.TestRunError):
        r.register_suite("bad", [dx.TestCase("t", "flaky")])


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX21_TESTRUN_VERSION == "dx-testrun.v1"
