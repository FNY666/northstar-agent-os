"""Tests for tree_19 (Octree)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_19")
def test_insert_count():
    o = t.OctNode(0, 0, 0, 10, 10, 10)
    o.insert((1, 2, 3))
    assert o.count() == 1
def test_out_of_bounds():
    o = t.OctNode(0, 0, 0, 10, 10, 10)
    assert o.insert((11, 0, 0)) is False
def test_box_query():
    o = t.OctNode(0, 0, 0, 10, 10, 10, cap=1)
    o.insert((1, 1, 1)); o.insert((9, 9, 9))
    assert o.count_in_box((0, 0, 0, 5, 5, 5)) == 1
def test_subdivide():
    o = t.OctNode(0, 0, 0, 10, 10, 10, cap=1)
    o.insert((1, 1, 1)); o.insert((2, 2, 2))
    assert len(o.children) == 8
