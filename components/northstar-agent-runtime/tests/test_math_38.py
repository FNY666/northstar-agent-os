"""Tests for math_38 (modular sqrt)."""
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


m = _load("math_38")


def test_residue():
    r = m.mod_sqrt(2, 7)
    assert r in (3, 4)
    assert (r * r) % 7 == 2


def test_non_residue():
    assert m.mod_sqrt(3, 7) is None


def test_general_prime():
    for p in (41, 101, 1009):
        for n in (2, 5, 10):
            r = m.mod_sqrt(n, p)
            if r is None:
                assert pow(n, (p - 1) // 2, p) == p - 1
            else:
                assert (r * r) % p == n % p


def test_edge():
    assert m.mod_sqrt(0, 7) == 0
    with pytest.raises(ValueError):
        m.mod_sqrt(2, 8)
