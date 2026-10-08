"""Tests for algo_32: AVL tree (simplified)."""

import importlib.util
import math
from pathlib import Path

import pytest

from algo_32 import AVLTree


def _load(name):
    path = Path(__file__).resolve().parent.parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


algo_32 = _load("algo_32")


def test_version_stdlib_and_simplified_docstring():
    assert algo_32.ALGO_32_VERSION == "algo-32.v1"
    assert algo_32.stdlib_only() is True
    assert "simplified" in algo_32.__doc__.lower()


def test_insert_search_normal():
    t = AVLTree()
    for k in [10, 20, 30, 40, 50, 25]:
        t.insert(k)
    for k in [10, 20, 30, 40, 50, 25]:
        assert t.search(k) is True
    assert t.search(99) is False
    assert t.inorder() == [10, 20, 25, 30, 40, 50]


def test_height_logarithmic_invariant():
    t = AVLTree()
    assert t.height() == 0
    n = 1000
    for k in range(n):  # sorted insert is the worst case for plain BST
        t.insert(k)
    assert t.height() <= 2 * math.log2(n + 1)
    t2 = AVLTree()
    for k in range(n, 0, -1):
        t2.insert(k)
    assert t2.height() <= 2 * math.log2(n + 1)
    assert t2.inorder() == list(range(1, n + 1))


def test_edge_cases_empty_single_duplicate():
    t = AVLTree()
    assert t.height() == 0
    assert t.search(1) is False
    assert t.inorder() == []
    t.insert(7)
    assert t.height() == 1
    assert t.search(7) is True
    t.insert(7)
    assert len(t) == 1
    assert t.height() == 1


def test_rebalance_triggers_all_rotation_cases():
    # Left-left / left-right / right-right / right-left patterns.
    for seq in ([30, 20, 10], [10, 20, 30], [30, 10, 20], [10, 30, 20]):
        t = AVLTree()
        for k in seq:
            t.insert(k)
        assert t.height() == 2, seq
        assert t.inorder() == sorted(seq)
