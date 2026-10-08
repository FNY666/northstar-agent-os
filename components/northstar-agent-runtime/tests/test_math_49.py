"""Tests for math_49 (Taylor series)."""
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


m = _load("math_49")


def test_exp():
    assert m.taylor_exp(1.0) == pytest.approx(math.e, abs=1e-12)
    assert m.taylor_exp(-2.0) == pytest.approx(math.exp(-2), abs=1e-10)
    assert m.taylor_exp(0.0) == pytest.approx(1.0)


def test_sin_cos():
    assert m.taylor_sin(math.pi / 6) == pytest.approx(0.5, abs=1e-12)
    assert m.taylor_cos(math.pi / 3) == pytest.approx(0.5, abs=1e-12)


def test_large_arg():
    assert m.taylor_sin(10.0) == pytest.approx(math.sin(10.0), abs=1e-9)
    assert m.taylor_cos(-7.0) == pytest.approx(math.cos(-7.0), abs=1e-9)


def test_bad_terms():
    with pytest.raises(ValueError):
        m.taylor_exp(1.0, terms=0)
