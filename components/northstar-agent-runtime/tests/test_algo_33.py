"""Tests for algo_33: red-black tree (simplified)."""

import importlib.util
from pathlib import Path

import pytest

from algo_33 import RBTree


def _load(name):
    path = Path(__file__).resolve().parent.parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


algo_33 = _load("algo_33")


def test_version_stdlib_and_simplified_docstring():
    assert algo_33.ALGO_33_VERSION == "algo-33.v1"
    assert algo_33.stdlib_only() is True
    assert "simplified" in algo_33.__doc__.lower()


def test_insert_search_normal():
    t = RBTree()
    keys = [10, 20, 30, 15, 25, 5, 1, 40]
    for k in keys:
        t.insert(k)
        assert t.check_invariants()
    for k in keys:
        assert t.search(k) is True
    assert t.search(100) is False
    assert t.inorder() == sorted(keys)


def test_red_black_invariants_hold_random():
    import random

    rng = random.Random(33)
    t = RBTree()
    keys = list(range(500))
    rng.shuffle(keys)
    for k in keys:
        t.insert(k)
        assert t.check_invariants()
    assert t.inorder() == list(range(500))


def test_edge_cases_empty_single_duplicate():
    t = RBTree()
    assert t.search(1) is False
    assert t.inorder() == []
    assert t.check_invariants()
    t.insert(7)
    assert t.search(7) is True
    assert t.inorder() == [7]
    assert t.check_invariants()
    t.insert(7)  # duplicate ignored
    assert len(t) == 1
    assert t.check_invariants()


def test_sorted_insert_stays_valid():
    t = RBTree()
    for k in range(100):
        t.insert(k)
        assert t.check_invariants()
    assert t.inorder() == list(range(100))
