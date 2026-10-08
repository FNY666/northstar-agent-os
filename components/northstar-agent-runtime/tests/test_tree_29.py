"""Tests for tree_29 (SS-tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_29")
def test_nn():
    s = t.SSTreeMock()
    s.insert((0, 0)); s.insert((10, 10))
    assert s.nn((1, 1)) == (0, 0)
def test_split_nn():
    s = t.SSTreeMock(cap=2)
    for p in [(0, 0), (1, 0), (9, 9), (10, 9)]: s.insert(p)
    assert s.nn((9.5, 9)) in ((9, 9), (10, 9))
def test_radius():
    s = t.SSTreeMock()
    s.insert((0, 0)); s.insert((4, 0))
    assert s.root.radius >= 2.0 - 1e-9
def test_single():
    s = t.SSTreeMock()
    s.insert((5, 5))
    assert s.nn((5, 5)) == (5, 5)
