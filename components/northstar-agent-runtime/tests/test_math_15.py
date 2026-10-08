"""Tests for math_15 (Miller-Rabin)."""
import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("math_15")


def test_small_primes():
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 101, 7919):
        assert m.is_probable_prime(p) is True


def test_composites():
    for c in (0, 1, 4, 9, 100, 561, 1105, 2**64 - 1):
        assert m.is_probable_prime(c) is False


def test_large_primes():
    assert m.is_probable_prime(2**61 - 1) is True
    assert m.is_probable_prime(10**18 + 3) is True


def test_large_composite():
    assert m.is_probable_prime(10**18 + 5) is False
    assert m.is_probable_prime((10**9 + 7) * (10**9 + 9)) is False
