"""Tests for math_37 (Legendre/Jacobi)."""
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


m = _load("math_37")


def test_legendre():
    assert m.legendre(2, 7) == 1
    assert m.legendre(3, 7) == -1
    assert m.legendre(7, 7) == 0
    with pytest.raises(ValueError):
        m.legendre(2, 8)


def test_jacobi():
    assert m.jacobi(2, 15) == 1
    assert m.jacobi(2, 21) == -1
    with pytest.raises(ValueError):
        m.jacobi(2, 10)


def test_jacobi_matches_legendre_on_primes():
    for p in (7, 11, 13):
        for a in range(1, p):
            assert m.jacobi(a, p) == m.legendre(a, p)


def test_multiplicativity():
    # (30/77) = (2/7)(3/7)(5/7)(2/11)(3/11)(5/11)
    assert m.jacobi(30, 77) == m.jacobi(2, 7) * m.jacobi(3, 7) * m.jacobi(5, 7) * m.jacobi(2, 11) * m.jacobi(3, 11) * m.jacobi(5, 11)
