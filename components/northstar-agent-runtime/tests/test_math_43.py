"""Tests for math_43 (signal)."""
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


m = _load("math_43")


def test_moving_average():
    assert m.moving_average([1, 2, 3, 4, 5], 3) == [2.0, 3.0, 4.0]
    assert m.moving_average([1, 2, 3], 1) == [1.0, 2.0, 3.0]
    with pytest.raises(ValueError):
        m.moving_average([1, 2], 3)


def test_convolve():
    assert m.convolve([1, 2, 3], [0, 1, 0.5]) == [0, 1, 2.5, 4.0, 1.5]
    assert m.convolve([1, 1], [1, 1]) == [1, 2, 1]


def test_convolve_commutative():
    assert m.convolve([1, 2], [3, 4, 5]) == m.convolve([3, 4, 5], [1, 2])


def test_cross_correlate():
    assert m.cross_correlate([1, 2, 3], [1, 2, 3]) == [3, 8, 14, 8, 3]
