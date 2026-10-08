"""Tests for tree_25 (Cover tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_25")
def test_nearest():
    c = t.CoverTreeMock()
    c.insert((0, 0)); c.insert((9, 9))
    assert c.nearest((1, 0)) == (0, 0)
def test_empty():
    assert t.CoverTreeMock().nearest((1, 1)) is None
def test_level():
    c = t.CoverTreeMock(base=2.0)
    assert c._level(5.0) == 3
def test_single_radius():
    c = t.CoverTreeMock(); c.insert((1, 1))
    assert c.cover_radius((1, 1)) == 0.0
