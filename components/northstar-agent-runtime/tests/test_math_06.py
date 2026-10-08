"""Tests for math_06 (fast pow)."""
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


m = _load("math_06")


def test_fast_pow_int():
    assert m.fast_pow(2, 10) == 1024
    assert m.fast_pow(2, 100) == 2**100
    assert m.fast_pow(7, 0) == 1


def test_fast_pow_negative_exp():
    assert abs(m.fast_pow(2, -2) - 0.25) < 1e-12
    assert abs(m.fast_pow(10, -1) - 0.1) < 1e-12


def test_fast_pow_mod():
    assert m.fast_pow_mod(2, 10, 1000) == 24
    assert m.fast_pow_mod(3, 123456, 1000000007) == pow(3, 123456, 1000000007)


def test_bad_args():
    with pytest.raises(ValueError):
        m.fast_pow_mod(2, -1, 5)
    with pytest.raises(ValueError):
        m.fast_pow_mod(2, 3, 0)
