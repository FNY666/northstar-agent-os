"""Tests for math_08 (determinant)."""
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


m = _load("math_08")


def test_det_2x2():
    assert m.det_2x2(1, 2, 3, 4) == -2
    assert m.det([[1, 2], [3, 4]]) == pytest.approx(-2.0)


def test_det_identity():
    assert m.det([[1, 0, 0], [0, 1, 0], [0, 0, 1]]) == pytest.approx(1.0)


def test_det_singular():
    assert m.det([[1, 2], [2, 4]]) == 0.0
    assert m.det([[1, 2, 3], [4, 5, 6], [7, 8, 9]]) == pytest.approx(0.0)


def test_det_known_3x3():
    assert m.det([[6, 1, 1], [4, -2, 5], [2, 8, 7]]) == pytest.approx(-306.0)
    with pytest.raises(ValueError):
        m.det([[1, 2, 3], [4, 5, 6]])
