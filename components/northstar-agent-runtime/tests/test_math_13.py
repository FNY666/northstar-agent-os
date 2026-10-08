"""Tests for math_13 (combinatorics)."""
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


m = _load("math_13")


def test_factorial():
    assert m.factorial(0) == 1
    assert m.factorial(5) == 120
    assert m.factorial(20) == 2432902008176640000
    with pytest.raises(ValueError):
        m.factorial(-1)


def test_nCr():
    assert m.nCr(5, 2) == 10
    assert m.nCr(10, 5) == 252
    assert m.nCr(7, 7) == 1
    with pytest.raises(ValueError):
        m.nCr(5, 6)


def test_nPr():
    assert m.nPr(5, 2) == 20
    assert m.nPr(5, 5) == 120
    with pytest.raises(ValueError):
        m.nPr(3, 4)


def test_multinomial():
    assert m.multinomial(2, 3) == 10
    assert m.multinomial(1, 1, 1) == 6
