"""Tests for math_33 (bisection)."""
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


m = _load("math_33")


def test_sqrt2():
    root = m.bisect_root(lambda x: x**2 - 2, 1.0, 2.0)
    assert root == pytest.approx(math.sqrt(2), abs=1e-9)


def test_cubic():
    root = m.bisect_root(lambda x: x**3 - x - 2, 1.0, 2.0)
    assert root == pytest.approx(1.5213797068, abs=1e-8)


def test_no_bracket():
    with pytest.raises(ValueError):
        m.bisect_root(lambda x: x**2 + 1, 0.0, 1.0)


def test_endpoint_root():
    assert m.bisect_root(lambda x: x - 2, 2.0, 5.0) == 2.0
