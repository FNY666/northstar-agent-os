"""Tests for tree_16 (Euler tour mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_16")
def test_ancestor():
    e = t.EulerTourMock(3, {0: [1, 2]})
    assert e.is_ancestor(0, 2) and not e.is_ancestor(1, 2)
def test_subtree_nodes():
    e = t.EulerTourMock(3, {0: [1], 1: [2]})
    assert sorted(e.subtree_nodes(1)) == [1, 2]
def test_subtree_sum():
    e = t.EulerTourMock(2, {0: [1]})
    assert e.subtree_sum(0, [5, 6]) == 11
def test_leaf():
    e = t.EulerTourMock(2, {0: [1]})
    assert e.subtree_nodes(1) == [1]
