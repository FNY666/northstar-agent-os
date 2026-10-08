"""Tests for tree_32 (UB-tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_32")
def test_z_order():
    assert t.z_order(2, 0) == 4
    assert t.z_order(0, 2) == 8
def test_sorted():
    u = t.UBTreeMock()
    u.insert(3, 0, "a"); u.insert(0, 0, "b")
    assert [z for z, _, _ in u.entries] == sorted(z for z, _, _ in u.entries)
def test_range():
    u = t.UBTreeMock()
    u.insert(1, 2, "x")
    assert u.range_query(0, 0, 2, 3) == ["x"]
def test_miss():
    u = t.UBTreeMock()
    u.insert(9, 9, "x")
    assert u.range_query(0, 0, 1, 1) == []
