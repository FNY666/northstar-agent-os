"""Tests for dx_22. coverage."""
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

dx = _load("dx_22")

def _cov():
    c = dx.CoverageTracker()
    c.record("a.py", [1, 2, 3, 5], 5)
    return c


def test_percent():
    assert _cov().percent("a.py") == 80.0


def test_uncovered():
    assert _cov().uncovered("a.py") == [4]


def test_full_coverage():
    c = dx.CoverageTracker()
    c.record("b.py", [1], 1)
    assert c.percent("b.py") == 100.0
    assert c.uncovered("b.py") == []


def test_out_of_range_raises():
    c = dx.CoverageTracker()
    with pytest.raises(dx.CoverageError):
        c.record("c.py", [6], 5)


def test_unknown_file_raises():
    with pytest.raises(dx.CoverageError):
        _cov().percent("nope.py")


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX22_COVERAGE_VERSION == "dx-coverage.v1"
