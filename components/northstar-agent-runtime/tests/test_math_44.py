"""Tests for math_44 (linear solve)."""
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


m = _load("math_44")


def test_2x2():
    x = m.gaussian_solve([[2, 1], [1, 3]], [5, 6])
    assert x[0] == pytest.approx(1.8)
    assert x[1] == pytest.approx(1.4)


def test_identity():
    assert m.gaussian_solve([[1, 0], [0, 1]], [7, 8]) == [7.0, 8.0]


def test_residual_3x3():
    A = [[3, 2, -1], [2, -2, 4], [-1, 0.5, -1]]
    b = [1, -2, 0]
    x = m.gaussian_solve(A, b)
    for i in range(3):
        assert sum(A[i][j] * x[j] for j in range(3)) == pytest.approx(b[i])


def test_singular():
    with pytest.raises(ValueError):
        m.gaussian_solve([[1, 2], [2, 4]], [1, 2])
    with pytest.raises(ValueError):
        m.gaussian_solve([[1, 2, 3], [4, 5, 6]], [1, 2])
