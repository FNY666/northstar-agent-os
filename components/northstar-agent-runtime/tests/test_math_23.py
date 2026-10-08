"""Tests for math_23 (complex ops)."""
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


m = _load("math_23")


def test_arithmetic():
    assert m.cadd(1 + 2j, 3 + 4j) == 4 + 6j
    assert m.csub(5 + 5j, 2 + 3j) == 3 + 2j
    assert m.cmul(1 + 1j, 1 - 1j) == 2 + 0j


def test_division():
    assert m.cdiv(1 + 1j, 1 - 1j) == pytest.approx(1j)
    with pytest.raises(ValueError):
        m.cdiv(1, 0)


def test_conj_abs():
    assert m.cconj(3 + 4j) == 3 - 4j
    assert m.cabs(3 + 4j) == pytest.approx(5.0)


def test_polar():
    assert m.cphase(1j) == pytest.approx(math.pi / 2)
    r, phi = m.cpolar(1 + 1j)
    assert r == pytest.approx(math.sqrt(2))
    assert phi == pytest.approx(math.pi / 4)
    assert m.crect(r, phi) == pytest.approx(1 + 1j)
