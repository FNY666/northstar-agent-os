"""Tests for math_20 (gradient descent)."""
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


m = _load("math_20")


def test_quadratic_1d():
    x, fx, _ = m.gradient_descent_1d(lambda t: t**2, lambda t: 2 * t, 5.0)
    assert x == pytest.approx(0.0, abs=1e-4)
    assert fx == pytest.approx(0.0, abs=1e-8)


def test_shifted_quadratic():
    x, fx, _ = m.gradient_descent_1d(
        lambda t: (t - 3) ** 2 + 5, lambda t: 2 * (t - 3), 0.0)
    assert x == pytest.approx(3.0, abs=1e-4)
    assert fx == pytest.approx(5.0, abs=1e-6)


def test_nd():
    xs, fxs, _ = m.gradient_descent_nd(
        lambda v: v[0] ** 2 + v[1] ** 2,
        lambda v: [2 * v[0], 2 * v[1]],
        [4.0, -3.0],
    )
    assert math.hypot(*xs) == pytest.approx(0.0, abs=1e-4)


def test_bad_lr():
    with pytest.raises(ValueError):
        m.gradient_descent_1d(lambda t: t, lambda t: 1, 0.0, lr=0)
