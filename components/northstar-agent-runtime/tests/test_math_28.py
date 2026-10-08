"""Tests for math_28 (Fibonacci)."""
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


m = _load("math_28")


def test_first_ten():
    assert [m.fib(i) for i in range(10)] == [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]


def test_large():
    assert m.fib(100) == 354224848179261915075
    assert m.fib(1000) % 10 == 5


def test_fib_mod():
    assert m.fib_mod(10, 1000) == 55
    assert m.fib_mod(1000, 10**9 + 7) == m.fib(1000) % (10**9 + 7)


def test_bad_args():
    with pytest.raises(ValueError):
        m.fib(-1)
    with pytest.raises(ValueError):
        m.fib_mod(5, 0)
