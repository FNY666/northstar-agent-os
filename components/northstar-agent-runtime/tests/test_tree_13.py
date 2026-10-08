"""Tests for tree_13 (Treap mock)."""
import importlib.util, sys, random
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_13")
def _build(keys):
    rng = random.Random(1); r = None
    for k in keys: r = t.treap_insert(r, k, rng)
    return r
def test_inorder_sorted():
    r = _build([4, 1, 3])
    out = []; t.inorder(r, out)
    assert out == [1, 3, 4]
def test_search():
    r = _build([4, 1])
    assert t.treap_search(r, 1) and not t.treap_search(r, 2)
def test_split():
    r = _build([1, 2, 3, 4])
    l, rr = t.split(r, 3)
    lo = []; hi = []
    t.inorder(l, lo); t.inorder(rr, hi)
    assert lo == [1, 2] and hi == [3, 4]
def test_merge():
    rng = random.Random(2)
    a = _build([1, 2]); b = _build([3, 4])
    m = t.merge(a, b)
    out = []; t.inorder(m, out)
    assert out == [1, 2, 3, 4]
