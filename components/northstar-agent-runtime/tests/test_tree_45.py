"""Tests for tree_45 (AA tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_45")
def _build(keys):
    r = None
    for k in keys: r = t.aa_insert(r, k)
    return r
def test_inorder():
    r = _build([3, 1, 2])
    out = []; t.inorder(r, out)
    assert out == [1, 2, 3]
def test_levels():
    r = _build(range(20))
    assert t.check_levels(r)
def test_dupe():
    r = _build([5, 5])
    out = []; t.inorder(r, out)
    assert out == [5]
def test_empty():
    out = []; t.inorder(None, out)
    assert out == []
