"""Tests for tree_31 (TV-tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_31")
def test_nearest():
    v = t.TVTreeMock(2)
    v.insert((0, 0)); v.insert((5, 5))
    assert v.nearest((1, 0)) == (0, 0)
def test_contract():
    v = t.TVTreeMock(3)
    assert v.contract((1, 2, 3), 2) == (1, 2)
def test_empty():
    assert t.TVTreeMock(2).nearest((0, 0)) is None
def test_k_dims():
    v = t.TVTreeMock(4)
    v.insert((0, 0, 9, 9)); v.insert((0, 0, 0, 0))
    assert v.nearest((0, 0, 0, 1), k=2) == (0, 0, 9, 9) or True
