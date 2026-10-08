"""Tests for tree_18 (Quadtree)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_18")
def test_insert_query():
    q = t.QuadNode(0, 0, 10, 10)
    q.insert((1, 1))
    assert q.query((0, 0, 2, 2)) == [(1, 1)]
def test_out_of_bounds():
    q = t.QuadNode(0, 0, 10, 10)
    assert q.insert((20, 20)) is False
def test_subdivide():
    q = t.QuadNode(0, 0, 10, 10, cap=2)
    for p in [(1, 1), (2, 2), (8, 8)]: q.insert(p)
    assert len(q.children) == 4
def test_empty_query():
    q = t.QuadNode(0, 0, 10, 10)
    assert q.query((0, 0, 1, 1)) == []
