"""Tests for tree_12 (Cartesian tree)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_12")
def test_root_is_min():
    r = t.build_cartesian([4, 2, 6])
    assert r.val == 2
def test_inorder_is_array():
    arr = [3, 1, 2]
    r = t.build_cartesian(arr)
    assert t.inorder_idx(r) == [0, 1, 2]
def test_heap_property():
    r = t.build_cartesian([5, 4, 3, 2, 1])
    assert t.is_min_heap(r)
def test_single():
    r = t.build_cartesian([7])
    assert r.val == 7 and r.left is None and r.right is None
