"""Tests for math_48 (rational)."""
import importlib.util
import sys
from fractions import Fraction
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("math_48")


def test_arithmetic():
    assert m.radd("1/3", "1/6") == Fraction(1, 2)
    assert m.rsub(1, "1/4") == Fraction(3, 4)
    assert m.rmul("2/3", "3/4") == Fraction(1, 2)
    assert m.rdiv(1, 3) == Fraction(1, 3)


def test_pow():
    assert m.rpow("2/3", 2) == Fraction(4, 9)
    assert m.rpow(2, 10) == 1024


def test_parse():
    assert m.rfrom("3/4") == Fraction(3, 4)
    assert m.rfrom("0.5") == Fraction(1, 2)


def test_div_zero():
    with pytest.raises(ValueError):
        m.rdiv(1, 0)
