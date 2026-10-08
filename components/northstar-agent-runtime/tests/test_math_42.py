"""Tests for math_42 (distributions)."""
import importlib.util
import math
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("math_42")


def test_binomial():
    assert m.binomial_pmf(10, 5, 0.5) == pytest.approx(0.24609375)
    assert sum(m.binomial_pmf(8, k, 0.3) for k in range(9)) == pytest.approx(1.0)


def test_poisson():
    assert m.poisson_pmf(3.0, 0) == pytest.approx(math.exp(-3))
    assert sum(m.poisson_pmf(2.0, k) for k in range(30)) == pytest.approx(1.0, abs=1e-9)


def test_geometric():
    assert m.geometric_pmf(0.5, 1) == pytest.approx(0.5)
    assert m.geometric_pmf(0.5, 3) == pytest.approx(0.125)
    with pytest.raises(ValueError):
        m.geometric_pmf(0.5, 0)


def test_expected_value():
    assert m.expected_value([1, 2, 3], [0.2, 0.3, 0.5]) == pytest.approx(2.3)
    with pytest.raises(ValueError):
        m.expected_value([1], [0])
