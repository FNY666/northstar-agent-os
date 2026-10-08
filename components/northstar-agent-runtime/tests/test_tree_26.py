"""Tests for tree_26 (Ball tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_26")
def test_nearest():
    r = t.build([(0, 0), (10, 10)])
    assert t.nearest(r, (1, 1)) == (0, 0)
def test_empty():
    assert t.nearest(None, (0, 0)) is None
def test_radius_covers():
    r = t.build([(0, 0), (2, 0)])
    import math
    assert r.radius >= 1.0 - 1e-9
def test_leaf():
    r = t.build([(3, 3)], leaf_size=2)
    assert t.nearest(r, (0, 0)) == (3, 3)
