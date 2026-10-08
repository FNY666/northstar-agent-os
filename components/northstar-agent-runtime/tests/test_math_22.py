"""Tests for math_22 (linear regression)."""
import importlib.util
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


m = _load("math_22")


def test_perfect_line():
    model = m.linregress([1, 2, 3, 4], [2, 4, 6, 8])
    assert model["slope"] == pytest.approx(2.0)
    assert model["intercept"] == pytest.approx(0.0)
    assert model["r_squared"] == pytest.approx(1.0)


def test_intercept():
    model = m.linregress([0, 1, 2, 3], [1, 3, 5, 7])
    assert model["slope"] == pytest.approx(2.0)
    assert model["intercept"] == pytest.approx(1.0)
    assert m.predict(model, 10) == pytest.approx(21.0)


def test_r_squared_partial():
    model = m.linregress([1, 2, 3], [1, 2, 2])
    assert 0.0 < model["r_squared"] < 1.0


def test_bad_input():
    with pytest.raises(ValueError):
        m.linregress([1], [2])
    with pytest.raises(ValueError):
        m.linregress([1, 1, 1], [2, 3, 4])
    with pytest.raises(ValueError):
        m.linregress([1, 2], [1])
