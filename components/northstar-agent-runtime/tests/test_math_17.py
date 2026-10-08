"""Tests for math_17 (vector ops)."""
import importlib.util
import math
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


m = _load("math_17")


def test_add_sub_scale():
    assert m.vadd([1, 2], [3, 4]) == [4, 6]
    assert m.vsub([3, 4], [1, 2]) == [2, 2]
    assert m.vscale([1, 2], 3) == [3, 6]
    with pytest.raises(ValueError):
        m.vadd([1, 2], [1, 2, 3])


def test_dot_cross():
    assert m.dot([1, 2, 3], [4, 5, 6]) == 32
    assert m.cross3([1, 0, 0], [0, 1, 0]) == [0, 0, 1]
    with pytest.raises(ValueError):
        m.cross3([1, 2], [3, 4])


def test_norm_normalize():
    assert m.norm([3, 4]) == pytest.approx(5.0)
    n = m.normalize([3, 4])
    assert m.norm(n) == pytest.approx(1.0)
    with pytest.raises(ValueError):
        m.normalize([0, 0])


def test_angle():
    assert m.angle([1, 0], [0, 1]) == pytest.approx(math.pi / 2)
    assert m.angle([1, 0], [1, 0]) == pytest.approx(0.0)
