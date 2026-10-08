"""Tests for tree_22 (Range tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_22")
def test_basic():
    r = t.RangeTreeMock([(1, 1), (2, 2), (3, 3)])
    assert r.query(1, 2, 1, 2) == [(1, 1), (2, 2)]
def test_empty():
    r = t.RangeTreeMock([(5, 5)])
    assert r.query(0, 1, 0, 1) == []
def test_y_filter():
    r = t.RangeTreeMock([(1, 1), (1, 9)])
    assert r.query(0, 2, 0, 5) == [(1, 1)]
def test_all():
    r = t.RangeTreeMock([(1, 2)])
    assert r.query(0, 9, 0, 9) == [(1, 2)]
