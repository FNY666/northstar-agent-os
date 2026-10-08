"""Tests for tree_11 (Sparse table)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_11")
def test_full_range():
    s = t.SparseTable([4, 1, 3])
    assert s.query(0, 2) == 1
def test_sub_range():
    s = t.SparseTable([5, 2, 8, 1])
    assert s.query(0, 1) == 2
def test_single():
    s = t.SparseTable([9, 7])
    assert s.query(1, 1) == 7
def test_min_at_end():
    s = t.SparseTable([3, 2, 1])
    assert s.query(0, 2) == 1
