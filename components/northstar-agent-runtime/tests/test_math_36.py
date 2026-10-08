"""Tests for math_36 (advanced combinatorics)."""
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


m = _load("math_36")


def test_catalan():
    assert [m.catalan(i) for i in range(6)] == [1, 1, 2, 5, 14, 42]
    with pytest.raises(ValueError):
        m.catalan(-1)


def test_bell():
    assert [m.bell(i) for i in range(6)] == [1, 1, 2, 5, 15, 52]


def test_stirling2():
    assert m.stirling2(4, 2) == 7
    assert m.stirling2(5, 1) == 1
    assert m.stirling2(5, 5) == 1
    assert m.stirling2(3, 5) == 0


def test_partitions():
    assert m.partitions(0) == 1
    assert m.partitions(5) == 7
    assert m.partitions(10) == 42
