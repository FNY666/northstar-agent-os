"""Tests for math_46 (quaternions)."""
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


m = _load("math_46")


def test_mul_basis():
    assert m.qmul((0, 1, 0, 0), (0, 0, 1, 0)) == (0, 0, 0, 1)  # i*j=k
    assert m.qmul((0, 0, 1, 0), (0, 1, 0, 0)) == (0, 0, 0, -1)  # j*i=-k


def test_conj_norm():
    assert m.qconj((1, 2, 3, 4)) == (1, -2, -3, -4)
    assert m.qnorm((1, 2, 3, 4)) == pytest.approx(math.sqrt(30))
    with pytest.raises(ValueError):
        m.qnormalize((0, 0, 0, 0))


def test_rotate_90_about_z():
    q = (math.cos(math.pi / 4), 0, 0, math.sin(math.pi / 4))
    r = m.qrotate((1, 0, 0), q)
    assert r[0] == pytest.approx(0.0, abs=1e-9)
    assert r[1] == pytest.approx(1.0, abs=1e-9)
    assert r[2] == pytest.approx(0.0, abs=1e-9)


def test_rotate_preserves_length():
    q = m.qnormalize((1, 2, 3, 4))
    r = m.qrotate((1, 2, 3), q)
    assert math.sqrt(sum(c * c for c in r)) == pytest.approx(math.sqrt(14))
