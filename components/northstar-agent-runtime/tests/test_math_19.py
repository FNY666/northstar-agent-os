"""Tests for math_19 (numerical integration)."""
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


m = _load("math_19")


def test_poly():
    f = lambda x: x**2  # noqa: E731
    assert m.trapezoid(f, 0, 1) == pytest.approx(1 / 3, abs=1e-6)
    assert m.simpson(f, 0, 1) == pytest.approx(1 / 3, abs=1e-12)
    assert m.midpoint(f, 0, 1) == pytest.approx(1 / 3, abs=1e-6)


def test_sin():
    assert m.simpson(math.sin, 0, math.pi) == pytest.approx(2.0, abs=1e-10)


def test_simpson_odd_n():
    assert m.simpson(lambda x: x, 0, 2, n=101) == pytest.approx(2.0, abs=1e-9)


def test_bad_args():
    with pytest.raises(ValueError):
        m.trapezoid(lambda x: x, 1, 0)
    with pytest.raises(ValueError):
        m.simpson(lambda x: x, 0, 1, n=0)
