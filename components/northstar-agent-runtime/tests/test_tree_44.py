"""Tests for tree_44 (Threaded binary tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_44")
def test_inorder():
    r = None
    for k in [2, 1, 3]: r = t.insert(r, k)
    assert t.inorder_threaded(r) == [1, 2, 3]
def test_empty():
    assert t.inorder_threaded(None) == []
def test_single():
    r = t.insert(None, 9)
    assert t.inorder_threaded(r) == [9]
def test_sorted_insert():
    r = None
    for k in [1, 2, 3, 4]: r = t.insert(r, k)
    assert t.inorder_threaded(r) == [1, 2, 3, 4]
