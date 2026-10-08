"""Tests for tree_39 (Game tree)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_39")
def test_minimax():
    n = t.GNode(children=[t.GNode(children=[t.GNode(1), t.GNode(4)], maximizing=False)], maximizing=True)
    assert t.minimax(n) == 1
def test_leaf():
    assert t.minimax(t.GNode(42)) == 42
def test_min_root():
    n = t.GNode(children=[t.GNode(5), t.GNode(3)], maximizing=False)
    assert t.minimax(n) == 3
def test_prune_correct():
    n = t.GNode(children=[
        t.GNode(children=[t.GNode(9), t.GNode(1)], maximizing=False),
        t.GNode(children=[t.GNode(8), t.GNode(8)], maximizing=False)], maximizing=True)
    assert t.minimax(n) == 8
