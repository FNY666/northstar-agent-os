"""Tests for math_18 (numerical differentiation)."""
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


m = _load("math_18")


def test_forward_diff():
    assert m.forward_diff(lambda x: x**2, 3.0) == pytest.approx(6.0, abs=1e-3)


def test_central_diff():
    assert m.central_diff(lambda x: x**3, 2.0) == pytest.approx(12.0, abs=1e-8)
    assert m.central_diff(math.sin, 0.0) == pytest.approx(1.0, abs=1e-8)


def test_second_central():
    assert m.second_central(lambda x: x**3, 2.0) == pytest.approx(12.0, abs=1e-3)
    assert m.second_central(lambda x: x**2, 5.0) == pytest.approx(2.0, abs=1e-4)


def test_bad_h():
    with pytest.raises(ValueError):
        m.central_diff(lambda x: x, 0.0, h=0)
    with pytest.raises(ValueError):
        m.forward_diff(lambda x: x, 0.0, h=-1)
