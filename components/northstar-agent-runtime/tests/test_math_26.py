"""Tests for math_26 (modular inverse)."""
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


m = _load("math_26")


def test_basic():
    assert m.modinv(3, 11) == 4
    assert m.modinv(1, 7) == 1
    assert m.modinv(10, 17) == 12


def test_inverse_property():
    for a, mod in ((17, 3120), (7, 100), (123, 10007)):
        assert (a * m.modinv(a, mod)) % mod == 1


def test_no_inverse():
    with pytest.raises(ValueError):
        m.modinv(6, 9)
    with pytest.raises(ValueError):
        m.modinv(4, 8)


def test_bad_modulus():
    with pytest.raises(ValueError):
        m.modinv(3, 0)
