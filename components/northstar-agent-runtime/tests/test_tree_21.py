"""Tests for tree_21 (Interval tree)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_21")
def _build(ivs):
    r = None
    for iv in ivs: r = t.insert(r, iv)
    return r
def test_overlap():
    r = _build([(1, 5), (6, 10)])
    out = []; t.query(r, (4, 7), out)
    assert sorted(out) == [(1, 5), (6, 10)]
def test_no_overlap():
    r = _build([(1, 2)])
    out = []; t.query(r, (5, 6), out)
    assert out == []
def test_point_query():
    r = _build([(1, 3), (5, 7)])
    out = []; t.query(r, (2, 2), out)
    assert out == [(1, 3)]
def test_empty():
    out = []; t.query(None, (0, 1), out)
    assert out == []
