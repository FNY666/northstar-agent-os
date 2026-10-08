"""Tests for math_45 (power iteration)."""
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


m = _load("math_45")


def test_diagonal():
    lam, v = m.power_iteration([[2, 0], [0, 1]])
    assert lam == pytest.approx(2.0, abs=1e-6)
    assert abs(v[0]) == pytest.approx(1.0, abs=1e-6)


def test_known():
    lam, _ = m.power_iteration([[4, 1], [2, 3]])
    assert lam == pytest.approx(5.0, abs=1e-4)


def test_eigen_equation():
    A = [[3, 1], [1, 3]]
    lam, v = m.power_iteration(A)
    Av = [sum(A[i][j] * v[j] for j in range(2)) for i in range(2)]
    for i in range(2):
        assert Av[i] == pytest.approx(lam * v[i], abs=1e-6)


def test_bad_matrix():
    with pytest.raises(ValueError):
        m.power_iteration([[1, 2, 3], [4, 5, 6]])
