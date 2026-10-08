"""Tests for math_11 (statistics)."""
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


m = _load("math_11")


def test_mean_median():
    assert m.mean([1, 2, 3, 4]) == 2.5
    assert m.median([3, 1, 2]) == 2.0
    assert m.median([1, 2, 3, 4]) == 2.5


def test_mode():
    assert m.mode([1, 2, 2, 3]) == 2
    assert m.mode([1, 2, 2, 3, 3]) == 2  # tie -> smallest


def test_variance_stdev():
    data = [2, 4, 4, 4, 5, 5, 7, 9]
    assert m.variance(data) == pytest.approx(4.0)
    assert m.stdev(data) == pytest.approx(2.0)
    assert m.data_range([1, 5, 3]) == 4


def test_empty():
    with pytest.raises(ValueError):
        m.mean([])
    with pytest.raises(ValueError):
        m.median([])
