"""Tests for tree_10 (Fenwick)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_10")
def test_prefix():
    f = t.Fenwick.from_list([1, 2, 3])
    assert f.prefix(2) == 6
def test_range():
    f = t.Fenwick.from_list([1, 2, 3, 4])
    assert f.range_sum(1, 2) == 5
def test_add():
    f = t.Fenwick.from_list([1, 1])
    f.add(0, 4)
    assert f.prefix(1) == 6
def test_single():
    f = t.Fenwick(1)
    f.add(0, 7)
    assert f.range_sum(0, 0) == 7
