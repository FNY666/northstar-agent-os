"""Tests for tree_04 (B-tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_04")
def test_sorted_keys():
    b = t.BTree(m=3)
    for k in [3, 1, 2]: b.insert(k)
    assert b.keys_sorted() == [1, 2, 3]
def test_split_on_overflow():
    b = t.BTree(m=3)
    for k in range(10): b.insert(k)
    assert b.keys_sorted() == list(range(10))
def test_search():
    b = t.BTree(m=4)
    for k in [8, 4]: b.insert(k)
    assert b.search(4) and not b.search(5)
def test_order5():
    b = t.BTree(m=5)
    for k in reversed(range(25)): b.insert(k)
    assert b.keys_sorted() == list(range(25))
