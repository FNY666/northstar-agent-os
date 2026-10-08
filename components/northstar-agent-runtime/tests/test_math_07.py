"""Tests for math_07 (matrix multiply)."""
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


m = _load("math_07")


def test_matmul():
    assert m.matmul([[1, 2], [3, 4]], [[5, 6], [7, 8]]) == [[19, 22], [43, 50]]
    assert m.matmul([[1, 2, 3]], [[4], [5], [6]]) == [[32]]


def test_matmul_mismatch():
    with pytest.raises(ValueError):
        m.matmul([[1, 2]], [[1, 2]])


def test_matvec_transpose_identity():
    assert m.matvec([[1, 2], [3, 4]], [1, 1]) == [3, 7]
    assert m.transpose([[1, 2, 3], [4, 5, 6]]) == [[1, 4], [2, 5], [3, 6]]
    assert m.identity(2) == [[1.0, 0.0], [0.0, 1.0]]


def test_bad_input():
    with pytest.raises(ValueError):
        m.matmul([], [[1]])
    with pytest.raises(ValueError):
        m.matmul([[1, 2], [3]], [[1], [2]])
    with pytest.raises(ValueError):
        m.identity(0)
