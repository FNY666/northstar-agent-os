"""Tests for math_35 (Monte Carlo pi)."""
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


m = _load("math_35")


def test_deterministic():
    assert m.estimate_pi(1000, seed=0) == m.estimate_pi(1000, seed=0)


def test_accuracy():
    assert m.estimate_pi(200000, seed=42) == pytest.approx(math.pi, abs=0.02)


def test_small_n():
    est = m.estimate_pi(10, seed=1)
    assert 0.0 <= est <= 4.0


def test_bad_n():
    with pytest.raises(ValueError):
        m.estimate_pi(0)
