"""Tests for algo_31: binary search tree."""

import importlib.util
from pathlib import Path

import pytest

from algo_31 import BST


def _load(name):
    path = Path(__file__).resolve().parent.parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


algo_31 = _load("algo_31")


def test_version_and_stdlib_only():
    assert algo_31.ALGO_31_VERSION == "algo-31.v1"
    assert algo_31.stdlib_only() is True


def test_insert_search_normal():
    b = BST()
    pairs = [(5, "five"), (3, "three"), (7, "seven"), (1, "one"), (9, "nine")]
    for k, v in pairs:
        b.insert(k, v)
    for k, v in pairs:
        assert b.search(k) == v
    assert b.search(42) is None
    assert len(b) == 5


def test_inorder_sorted_invariant():
    import random

    b = BST()
    keys = list(range(200))
    random.Random(31).shuffle(keys)
    for k in keys:
        b.insert(k)
    assert b.inorder() == sorted(keys)


def test_edge_cases_empty_single_duplicate():
    b = BST()
    assert b.search(1) is None
    assert b.inorder() == []
    assert len(b) == 0
    b.insert(10)
    assert b.search(10) is None  # default value is None
    assert b.inorder() == [10]
    b.insert(10, "second")  # duplicate ignored, first wins
    assert b.search(10) is None
    assert b.inorder() == [10]
    assert len(b) == 1


def test_duplicate_keeps_first_value():
    b = BST()
    b.insert("k", "first")
    b.insert("k", "second")
    b.insert("k", "third")
    assert b.search("k") == "first"
    assert len(b) == 1


def test_insert_default_value_none():
    b = BST()
    b.insert(7)
    b.insert(3)
    assert b.search(7) is None
    assert b.inorder() == [3, 7]
