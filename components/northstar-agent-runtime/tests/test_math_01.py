"""Tests for math_01 (prime checking)."""
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


m = _load("math_01")


def test_known_primes():
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 7919, 104729):
        assert m.is_prime(p) is True


def test_known_composites():
    for c in (0, 1, -7, 4, 9, 100, 1000, 999983 * 999979):
        assert m.is_prime(c) is False


def test_next_prime():
    assert m.next_prime(10) == 11
    assert m.next_prime(1) == 2
    assert m.next_prime(2) == 3
    assert m.next_prime(100) == 101


def test_prev_prime():
    assert m.prev_prime(10) == 7
    assert m.prev_prime(3) == 2
    assert m.prev_prime(100) == 97
    with pytest.raises(ValueError):
        m.prev_prime(2)
