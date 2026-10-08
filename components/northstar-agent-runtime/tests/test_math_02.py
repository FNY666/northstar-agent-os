"""Tests for math_02 (sieve)."""
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


m = _load("math_02")


def test_sieve_small():
    assert m.sieve(20) == [2, 3, 5, 7, 11, 13, 17, 19]
    assert m.sieve(2) == [2]
    assert m.sieve(1) == []
    assert m.sieve(0) == []


def test_prime_pi():
    assert m.prime_pi(10) == 4
    assert m.prime_pi(100) == 25
    assert m.prime_pi(1000) == 168


def test_nth_prime():
    assert m.nth_prime(1) == 2
    assert m.nth_prime(6) == 13
    assert m.nth_prime(100) == 541
    with pytest.raises(ValueError):
        m.nth_prime(0)


def test_sieve_consistency():
    primes = m.sieve(200)
    assert len(primes) == m.prime_pi(200)
    assert primes[-1] == m.nth_prime(len(primes))
