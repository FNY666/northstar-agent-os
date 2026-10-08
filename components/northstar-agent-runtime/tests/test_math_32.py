"""Tests for math_32 (Newton-Raphson)."""
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


m = _load("math_32")


def test_sqrt2():
    root = m.newton(lambda x: x**2 - 2, lambda x: 2 * x, 1.0)
    assert root == pytest.approx(math.sqrt(2), abs=1e-9)


def test_cbrt():
    root = m.newton(lambda x: x**3 - 27, lambda x: 3 * x**2, 5.0)
    assert root == pytest.approx(3.0, abs=1e-9)


def test_no_converge():
    with pytest.raises(ValueError):
        m.newton(lambda x: x**2 + 1, lambda x: 2 * x, 0.0, max_iter=5)


def test_zero_derivative():
    with pytest.raises(ValueError):
        m.newton(lambda x: x**3, lambda x: 3 * x**2, 0.0)
