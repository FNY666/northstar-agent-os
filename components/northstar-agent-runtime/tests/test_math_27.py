"""Tests for math_27 (CRT)."""
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


m = _load("math_27")


def test_coprime():
    x, M = m.crt([2, 3], [3, 5])
    assert (x, M) == (8, 15)


def test_three():
    x, M = m.crt([2, 3, 2], [3, 5, 7])
    assert M == 105
    assert (x % 3, x % 5, x % 7) == (2, 3, 2)


def test_non_coprime_consistent():
    x, M = m.crt([2, 4], [4, 6])
    assert (x, M) == (10, 12)


def test_inconsistent():
    with pytest.raises(ValueError):
        m.crt([1, 2], [4, 6])
    with pytest.raises(ValueError):
        m.crt([], [])
