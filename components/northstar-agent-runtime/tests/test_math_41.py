"""Tests for math_41 (second-order statistics)."""
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


m = _load("math_41")


def test_covariance():
    assert m.covariance([1, 2, 3], [1, 2, 3]) == pytest.approx(2 / 3)
    assert m.covariance([1, 2, 3], [3, 2, 1]) == pytest.approx(-2 / 3)


def test_correlation():
    assert m.correlation([1, 2, 3], [2, 4, 6]) == pytest.approx(1.0)
    assert m.correlation([1, 2, 3], [6, 4, 2]) == pytest.approx(-1.0)
    with pytest.raises(ValueError):
        m.correlation([1, 1, 1], [2, 3, 4])


def test_zscores():
    zs = m.zscores([1, 2, 3, 4])
    assert sum(zs) == pytest.approx(0.0, abs=1e-9)
    assert sum(z * z for z in zs) / len(zs) == pytest.approx(1.0)


def test_weighted_mean():
    assert m.weighted_mean([1, 2, 3], [1, 1, 2]) == pytest.approx(2.25)
    with pytest.raises(ValueError):
        m.weighted_mean([1], [0])
