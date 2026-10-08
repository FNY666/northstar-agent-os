"""Tests for math_25 (continued fractions)."""
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


m = _load("math_25")


def test_known_expansion():
    assert m.to_cf(3.25) == [3, 4]
    assert m.to_cf(math.pi)[:4] == [3, 7, 15, 1]


def test_round_trip():
    for x in (2.5, 3.245, math.e, 0.333):
        assert m.from_cf(m.to_cf(x)) == pytest.approx(x, abs=1e-9)


def test_from_cf():
    assert m.from_cf([3, 4, 12, 4]) == pytest.approx(3.245)
    with pytest.raises(ValueError):
        m.from_cf([])


def test_bad_args():
    with pytest.raises(ValueError):
        m.to_cf(1.5, max_terms=0)
