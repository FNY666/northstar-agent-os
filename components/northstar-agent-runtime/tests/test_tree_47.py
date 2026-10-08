"""Tests for tree_47 (Weight-balanced mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_47")
def _build(keys):
    r = None
    for k in keys: r = t.wb_insert(r, k)
    return r
def test_inorder():
    r = _build([4, 2, 6])
    out = []; t.inorder(r, out)
    assert out == [2, 4, 6]
def test_size():
    r = _build(range(10))
    assert r.size == 10
def test_dupe():
    r = _build([1, 1])
    assert r.size == 1
def test_reverse():
    r = _build(reversed(range(15)))
    out = []; t.inorder(r, out)
    assert out == list(range(15))
