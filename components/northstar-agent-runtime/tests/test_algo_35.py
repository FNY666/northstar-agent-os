"""Tests for algo_35: segment tree (range sum)."""

import importlib.util
from pathlib import Path

import pytest

from algo_35 import SegmentTree


def _load(name):
    path = Path(__file__).resolve().parent.parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


algo_35 = _load("algo_35")


def test_version_and_stdlib_only():
    assert algo_35.ALGO_35_VERSION == "algo-35.v1"
    assert algo_35.stdlib_only() is True


def test_query_normal():
    data = [2, 4, 6, 8, 10]
    st = SegmentTree(data)
    assert st.query(0, 4) == 30
    assert st.query(1, 3) == 18
    assert st.query(2, 2) == 6
    assert st.query(0, 0) == 2
    assert st.query(4, 4) == 10


def test_update_then_query():
    st = SegmentTree([1, 1, 1, 1, 1])
    st.update(0, 5)
    st.update(4, 10)
    assert st.query(0, 4) == 18
    assert st.query(0, 0) == 5
    assert st.query(4, 4) == 10
    st.update(2, 0)
    assert st.query(0, 4) == 17


def test_against_brute_force():
    import random

    rng = random.Random(35)
    data = [rng.randint(-100, 100) for _ in range(50)]
    st = SegmentTree(data)
    for _ in range(200):
        l = rng.randint(0, 49)
        r = rng.randint(l, 49)
        assert st.query(l, r) == sum(data[l : r + 1])
    for _ in range(20):
        i = rng.randint(0, 49)
        v = rng.randint(-100, 100)
        data[i] = v
        st.update(i, v)
        l = rng.randint(0, 49)
        r = rng.randint(l, 49)
        assert st.query(l, r) == sum(data[l : r + 1])


def test_edge_cases_empty_single():
    st = SegmentTree([42])
    assert st.query(0, 0) == 42
    st.update(0, -1)
    assert st.query(0, 0) == -1
    empty = SegmentTree([])
    assert len(empty) == 0
    with pytest.raises(IndexError):
        empty.query(0, 0)
    with pytest.raises(IndexError):
        empty.update(0, 1)


def test_invalid_ranges():
    st = SegmentTree([1, 2, 3])
    with pytest.raises(IndexError):
        st.query(2, 1)
    with pytest.raises(IndexError):
        st.query(-1, 2)
    with pytest.raises(IndexError):
        st.query(0, 3)
    with pytest.raises(IndexError):
        st.update(3, 0)
