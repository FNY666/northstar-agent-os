"""Tests for tree_34 (Binary heap)."""
import importlib.util, sys
import pytest
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_34")
def test_push_pop_order():
    h = t.BinaryHeap()
    for x in [3, 1, 2]: h.push(x)
    assert [h.pop() for _ in range(3)] == [1, 2, 3]
def test_peek():
    h = t.BinaryHeap(); h.push(9); h.push(4)
    assert h.peek() == 4
def test_empty_pop():
    with pytest.raises(IndexError):
        t.BinaryHeap().pop()
def test_is_heap():
    h = t.BinaryHeap()
    for x in [7, 2, 9, 1]: h.push(x)
    assert h.is_heap()
