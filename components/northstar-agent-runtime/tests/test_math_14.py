"""Tests for math_14 (Euler totient)."""
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


m = _load("math_14")


def test_phi_primes():
    assert m.phi(7) == 6
    assert m.phi(13) == 12


def test_phi_composites():
    assert m.phi(1) == 1
    assert m.phi(9) == 6
    assert m.phi(10) == 4
    assert m.phi(36) == 12
    with pytest.raises(ValueError):
        m.phi(0)


def test_phi_range():
    assert m.phi_range(10) == [0, 1, 1, 2, 2, 4, 2, 6, 4, 6, 4]
    assert m.phi_range(0) == [0]


def test_phi_range_consistency():
    pr = m.phi_range(50)
    for k in range(1, 51):
        assert pr[k] == m.phi(k)
