"""Tests for math_04 (LCM)."""
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


m = _load("math_04")


def test_lcm_basic():
    assert m.lcm(4, 6) == 12
    assert m.lcm(7, 5) == 35
    assert m.lcm(21, 6) == 42


def test_lcm_zero():
    assert m.lcm(0, 5) == 0
    assert m.lcm(5, 0) == 0


def test_lcm_sign():
    assert m.lcm(-4, 6) == 12
    assert m.lcm(4, -6) == 12


def test_lcm_list():
    assert m.lcm_list([2, 3, 4]) == 12
    assert m.lcm_list([4, 6, 8]) == 24
    with pytest.raises(ValueError):
        m.lcm_list([])
