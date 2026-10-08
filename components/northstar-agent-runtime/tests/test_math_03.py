"""Tests for math_03 (GCD)."""
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


m = _load("math_03")


def test_gcd_basic():
    assert m.gcd(12, 18) == 6
    assert m.gcd(7, 13) == 1
    assert m.gcd(0, 5) == 5
    assert m.gcd(0, 0) == 0


def test_gcd_sign():
    assert m.gcd(-12, 18) == 6
    assert m.gcd(12, -18) == 6


def test_gcd_list():
    assert m.gcd_list([12, 18, 24]) == 6
    assert m.gcd_list([7]) == 7
    with pytest.raises(ValueError):
        m.gcd_list([])


def test_extended_gcd_identity():
    for a, b in ((30, 12), (17, 5), (100, 35), (0, 7)):
        g, x, y = m.extended_gcd(a, b)
        assert g == m.gcd(a, b)
        assert a * x + b * y == g
