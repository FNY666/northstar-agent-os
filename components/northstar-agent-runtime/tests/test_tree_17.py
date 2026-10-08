"""Tests for tree_17 (KD-tree)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_17")
def test_exact():
    r = t.build([(1, 1), (2, 2)])
    assert t.nearest(r, (1, 1)) == (1, 1)
def test_nearest():
    r = t.build([(0, 0), (10, 10)])
    assert t.nearest(r, (1, 1)) == (0, 0)
def test_empty():
    assert t.nearest(None, (5, 5)) is None
def test_single():
    r = t.build([(3, 4)])
    assert t.nearest(r, (0, 0)) == (3, 4)
