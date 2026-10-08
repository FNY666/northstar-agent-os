"""Tests for tree_20 (R-tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_20")
def test_query_hit():
    r = t.RTreeMock()
    r.insert((0, 0, 1, 1), "x")
    assert r.query((0, 0, 1, 1)) == ["x"]
def test_query_miss():
    r = t.RTreeMock()
    r.insert((0, 0, 1, 1), "x")
    assert r.query((5, 5, 6, 6)) == []
def test_split():
    r = t.RTreeMock(cap=2)
    for i in range(5): r.insert((i, i, i + 1, i + 1), i)
    assert sorted(r.query((0, 0, 10, 10))) == [0, 1, 2, 3, 4]
def test_overlap_partial():
    r = t.RTreeMock()
    r.insert((0, 0, 4, 4), "big")
    assert r.query((3, 3, 5, 5)) == ["big"]
