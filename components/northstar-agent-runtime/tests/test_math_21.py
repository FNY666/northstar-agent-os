"""Tests for math_21 (interpolation)."""
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


m = _load("math_21")


def test_linear_interp():
    assert m.linear_interp(0.5, 0, 0, 1, 10) == 5.0
    assert m.linear_interp(2, 0, 1, 4, 9) == 5.0
    with pytest.raises(ValueError):
        m.linear_interp(1, 2, 0, 2, 5)


def test_lagrange_quadratic():
    xs, ys = [0, 1, 2], [1, 2, 5]  # x^2 + 1
    assert m.lagrange(3, xs, ys) == pytest.approx(10.0)


def test_lagrange_hits_nodes():
    xs, ys = [0.0, 1.5, 3.0], [2.0, -1.0, 4.0]
    for xi, yi in zip(xs, ys):
        assert m.lagrange(xi, xs, ys) == pytest.approx(yi)


def test_lagrange_bad():
    with pytest.raises(ValueError):
        m.lagrange(0, [1, 1], [2, 3])
    with pytest.raises(ValueError):
        m.lagrange(0, [], [])
