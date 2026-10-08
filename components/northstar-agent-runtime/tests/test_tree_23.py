"""Tests for tree_23 (VP-tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_23")
def test_exact():
    v = t.VPTreeMock([(1, 2), (3, 4)])
    assert v.nearest((3, 4)) == (3, 4)
def test_near():
    v = t.VPTreeMock([(0, 0), (10, 0)])
    assert v.nearest((1, 0)) == (0, 0)
def test_empty():
    assert t.VPTreeMock([]).nearest((1, 1)) is None
def test_single():
    v = t.VPTreeMock([(7, 7)])
    assert v.nearest((0, 0)) == (7, 7)
