"""Tests for math_50 (big number)."""
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


m = _load("math_50")


def test_factorial_digits():
    assert m.factorial_digits(0) == 1
    assert m.factorial_digits(5) == 3
    assert m.factorial_digits(100) == 158
    with pytest.raises(ValueError):
        m.factorial_digits(-1)


def test_lucas():
    assert m.lucas_binom_mod(10, 3, 7) == 1
    assert m.lucas_binom_mod(1000, 500, 7) == math.comb(1000, 500) % 7
    assert m.lucas_binom_mod(5, 2, 13) == 10


def test_lucas_edge():
    assert m.lucas_binom_mod(5, 6, 7) == 0
    assert m.lucas_binom_mod(0, 0, 7) == 1


def test_trailing_zeros():
    assert m.trailing_zeros_factorial(100) == 24
    assert m.trailing_zeros_factorial(5) == 1
    assert m.trailing_zeros_factorial(0) == 0
