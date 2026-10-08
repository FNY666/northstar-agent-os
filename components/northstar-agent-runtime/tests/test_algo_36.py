"""Tests for algo_36: Fenwick tree."""

import importlib.util
from pathlib import Path

import pytest

from algo_36 import Fenwick


def _load(name):
    path = Path(__file__).resolve().parent.parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


algo_36 = _load("algo_36")


def test_version_and_stdlib_only():
    assert algo_36.ALGO_36_VERSION == "algo-36.v1"
    assert algo_36.stdlib_only() is True


def test_prefix_and_range_sum_normal():
    f = Fenwick([3, 1, 4, 1, 5, 9, 2, 6])
    assert f.prefix_sum(0) == 3
    assert f.prefix_sum(3) == 9
    assert f.prefix_sum(7) == 31
    assert f.range_sum(0, 7) == 31
    assert f.range_sum(2, 5) == 19
    assert f.range_sum(4, 4) == 5


def test_add_updates():
    f = Fenwick([1, 2, 3, 4])
    f.add(1, 10)
    assert f.get(1) == 12
    assert f.prefix_sum(3) == 20
    f.add(0, -1)
    assert f.prefix_sum(0) == 0
    assert f.range_sum(0, 3) == 19


def test_against_brute_force():
    import random

    rng = random.Random(36)
    data = [rng.randint(-50, 50) for _ in range(40)]
    f = Fenwick(data)
    for _ in range(100):
        i = rng.randint(0, 39)
        assert f.prefix_sum(i) == sum(data[: i + 1])
        l = rng.randint(0, 39)
        r = rng.randint(l, 39)
        assert f.range_sum(l, r) == sum(data[l : r + 1])
    for _ in range(20):
        i = rng.randint(0, 39)
        d = rng.randint(-50, 50)
        data[i] += d
        f.add(i, d)
    assert f.prefix_sum(39) == sum(data)


def test_edge_cases_empty_single():
    f = Fenwick([7])
    assert f.prefix_sum(0) == 7
    assert f.range_sum(0, 0) == 7
    f.add(0, 3)
    assert f.get(0) == 10
    empty = Fenwick()
    assert len(empty) == 0
    with pytest.raises(IndexError):
        empty.prefix_sum(0)
    with pytest.raises(IndexError):
        empty.add(0, 1)
    with pytest.raises(IndexError):
        empty.range_sum(0, 0)


def test_out_of_range_indices():
    f = Fenwick([1, 2, 3])
    with pytest.raises(IndexError):
        f.prefix_sum(3)
    with pytest.raises(IndexError):
        f.add(-1, 1)
    with pytest.raises(IndexError):
        f.range_sum(2, 1)
