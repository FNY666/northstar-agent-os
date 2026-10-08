"""Tests for math_29 (factorization)."""
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


m = _load("math_29")


def test_factorize():
    assert m.factorize(360) == {2: 3, 3: 2, 5: 1}
    assert m.factorize(13) == {13: 1}
    assert m.factorize(1) == {}
    with pytest.raises(ValueError):
        m.factorize(0)


def test_reconstruct():
    for n in (1, 12, 360, 997):
        prod = 1
        for p, e in m.factorize(n).items():
            prod *= p**e
        assert prod == n


def test_divisors():
    assert m.divisors(12) == [1, 2, 3, 4, 6, 12]
    assert m.num_divisors(36) == 9
    assert m.num_divisors(13) == 2


def test_squarefree():
    assert m.is_squarefree(30) is True
    assert m.is_squarefree(18) is False
