"""Tests for math_40 (order statistics)."""
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


m = _load("math_40")


def test_kth_smallest():
    assert m.kth_smallest([3, 1, 2], 1) == 2
    assert m.kth_smallest([5, 4, 3, 2, 1], 0) == 1
    assert m.kth_smallest([5, 4, 3, 2, 1], 4) == 5


def test_kth_matches_sorted():
    import random
    rng = random.Random(7)
    xs = [rng.randint(0, 1000) for _ in range(200)]
    s = sorted(xs)
    for k in (0, 50, 199):
        assert m.kth_smallest(xs, k) == s[k]


def test_running_median():
    assert m.running_median([1, 3, 2]) == [1.0, 2.0, 2.0]
    assert m.running_median([5, 15, 1, 3]) == [5.0, 10.0, 5.0, 4.0]


def test_bad_args():
    with pytest.raises(ValueError):
        m.kth_smallest([], 0)
    with pytest.raises(IndexError):
        m.kth_smallest([1, 2], 5)
