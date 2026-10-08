"""Tests for math_24 (polynomials)."""
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


m = _load("math_24")


def test_peval():
    assert m.peval([1, 2, 3], 2) == 17
    assert m.peval([5], 100) == 5
    with pytest.raises(ValueError):
        m.peval([], 1)


def test_padd():
    assert m.padd([1, 2], [3, 4, 5]) == [4, 6, 5]
    assert m.padd([1, 1], [-1, -1]) == [0]


def test_pmul():
    assert m.pmul([1, 1], [1, 1]) == [1, 2, 1]
    assert m.pmul([2], [3, 4]) == [6, 8]


def test_pderivative():
    assert m.pderivative([1, 2, 3]) == [2, 6]
    assert m.pderivative([5]) == [0]
    # derivative of product check at a point
    p = m.pmul([1, 1], [0, 1])  # x + x^2
    assert m.peval(m.pderivative(p), 3) == 7  # 1 + 2x at 3
