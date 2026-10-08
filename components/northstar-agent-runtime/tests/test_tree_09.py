"""Tests for tree_09 (Segment tree)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_09")
def test_range_sum():
    s = t.SegmentTree([1, 2, 3, 4])
    assert s.query(0, 3) == 10
def test_partial():
    s = t.SegmentTree([5, 5, 5])
    assert s.query(0, 1) == 10
def test_update():
    s = t.SegmentTree([1, 1, 1])
    s.update(1, 5)
    assert s.query(0, 2) == 7
def test_single():
    s = t.SegmentTree([9])
    assert s.query(0, 0) == 9
