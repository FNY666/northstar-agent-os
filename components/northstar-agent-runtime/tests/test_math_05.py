"""Tests for math_05 (modular arithmetic)."""
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


m = _load("math_05")


def test_basic_ops():
    assert m.mod_add(7, 8, 10) == 5
    assert m.mod_sub(3, 8, 10) == 5
    assert m.mod_mul(7, 8, 10) == 6
    assert m.mod_neg(3, 10) == 7


def test_mod_pow():
    assert m.mod_pow(2, 10, 1000) == 24
    assert m.mod_pow(3, 0, 5) == 1
    assert m.mod_pow(2, 100, 101) == pow(2, 100, 101)


def test_normalization():
    assert m.mod_add(-3, -4, 10) == 3
    assert m.mod_mul(-2, 3, 7) == 1


def test_bad_modulus():
    with pytest.raises(ValueError):
        m.mod_add(1, 2, 0)
    with pytest.raises(ValueError):
        m.mod_pow(2, 3, -5)
    with pytest.raises(ValueError):
        m.mod_pow(2, -1, 5)
