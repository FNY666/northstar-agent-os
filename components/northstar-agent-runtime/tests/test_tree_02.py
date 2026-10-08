"""Tests for tree_02 (AVL)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_02")
def _build(keys):
    r = None
    for k in keys: r = t.avl_insert(r, k)
    return r
def test_sorted_insert_balanced():
    r = _build(range(20))
    assert t.is_balanced(r)
def test_inorder_sorted():
    r = _build([5, 1, 9, 3])
    out = []; t.inorder(r, out)
    assert out == [1, 3, 5, 9]
def test_height_logarithmic():
    r = _build(range(100))
    assert r.height <= 8
def test_dupes_ignored():
    r = _build([3, 3, 3])
    out = []; t.inorder(r, out)
    assert out == [3]
