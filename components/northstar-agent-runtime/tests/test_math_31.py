"""Tests for math_31 (sequences)."""
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


m = _load("math_31")


def test_arith():
    assert m.arith_nth(2, 3, 4) == 11
    assert m.arith_sum(1, 1, 100) == 5050
    with pytest.raises(ValueError):
        m.arith_nth(1, 1, 0)


def test_geom():
    assert m.geom_nth(2, 3, 4) == 54
    assert m.geom_sum(1, 2, 4) == 15
    assert m.geom_sum(5, 1, 10) == 50


def test_harmonic():
    assert m.harmonic(1) == pytest.approx(1.0)
    assert m.harmonic(4) == pytest.approx(1 + 1/2 + 1/3 + 1/4)
    with pytest.raises(ValueError):
        m.harmonic(0)


def test_geom_sum_matches_terms():
    a1, r, n = 3, 2, 6
    terms = [m.geom_nth(a1, r, k) for k in range(1, n + 1)]
    assert m.geom_sum(a1, r, n) == pytest.approx(sum(terms))
