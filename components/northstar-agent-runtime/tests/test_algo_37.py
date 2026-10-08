"""Tests for algo_37: binary min-heap."""

import importlib.util
from pathlib import Path

import pytest

from algo_37 import MinHeap


def _load(name):
    path = Path(__file__).resolve().parent.parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


algo_37 = _load("algo_37")


def test_version_stdlib_and_no_heapq_core():
    assert algo_37.ALGO_37_VERSION == "algo-37.v1"
    assert algo_37.stdlib_only() is True
    import ast

    tree = ast.parse(open(algo_37.__file__, encoding="utf-8").read())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert "heapq" not in imports, "core logic must be manual, not heapq"


def test_push_pop_ascending_order_invariant():
    import random

    rng = random.Random(37)
    h = MinHeap()
    vals = [rng.randint(0, 1000) for _ in range(300)]
    for v in vals:
        h.push(v)
    assert len(h) == 300
    assert h.peek() == min(vals)
    popped = [h.pop() for _ in range(300)]
    assert popped == sorted(vals)
    assert len(h) == 0


def test_push_pop_normal():
    h = MinHeap()
    for x in [5, 3, 8, 1, 9, 2]:
        h.push(x)
    assert h.peek() == 1
    assert len(h) == 6
    assert h.pop() == 1
    assert h.pop() == 2
    assert h.peek() == 3
    assert h.pop() == 3
    assert len(h) == 3


def test_edge_cases_empty_single_duplicate():
    h = MinHeap()
    assert len(h) == 0
    assert not h
    with pytest.raises(IndexError):
        h.pop()
    with pytest.raises(IndexError):
        h.peek()
    h.push(42)
    assert bool(h)
    assert h.peek() == 42
    assert h.pop() == 42
    assert len(h) == 0
    for _ in range(5):
        h.push(7)
    assert [h.pop() for _ in range(5)] == [7, 7, 7, 7, 7]


def test_interleaved_push_pop():
    h = MinHeap()
    h.push(10)
    h.push(4)
    assert h.pop() == 4
    h.push(6)
    h.push(1)
    assert h.pop() == 1
    assert h.pop() == 6
    assert h.pop() == 10
    assert len(h) == 0
