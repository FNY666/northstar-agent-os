"""Tests for tree_27 (M-tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_27")
def test_range():
    m = t.MTreeMock()
    m.insert((0, 0), "a"); m.insert((5, 5), "b")
    assert m.range_query((0, 0), 1.0) == ["a"]
def test_miss():
    m = t.MTreeMock()
    m.insert((0, 0), "a")
    assert m.range_query((9, 9), 1.0) == []
def test_split():
    m = t.MTreeMock(cap=2)
    for i in range(6): m.insert((i, 0), i)
    assert sorted(m.range_query((0, 0), 100.0)) == [0, 1, 2, 3, 4, 5]
def test_zero_radius():
    m = t.MTreeMock()
    m.insert((2, 2), "x")
    assert m.range_query((2, 2), 0.0) == ["x"]
