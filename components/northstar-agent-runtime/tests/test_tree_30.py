"""Tests for tree_30 (SR-tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_30")
def test_query():
    s = t.SRTreeMock()
    s.insert((0, 0, 1, 1), "a")
    assert s.query((0, 0, 1, 1)) == ["a"]
def test_miss():
    s = t.SRTreeMock()
    s.insert((0, 0, 1, 1), "a")
    assert s.query((2, 2, 3, 3)) == []
def test_sphere():
    s = t.SRTreeMock()
    s.insert((0, 0, 2, 2), "a")
    assert s.root.sphere is not None
def test_split():
    s = t.SRTreeMock(cap=2)
    for i in range(4): s.insert((i * 5, 0, i * 5 + 1, 1), i)
    assert sorted(s.query((0, 0, 20, 1))) == [0, 1, 2, 3]
