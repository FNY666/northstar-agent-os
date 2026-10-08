"""Tests for tree_50 (LCA)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_50")
def _t():
    return t.LCATree(6, {0: [1, 2], 1: [3, 4], 2: [5]})
def test_lca_siblings():
    assert _t().lca(3, 4) == 1
def test_lca_cross():
    assert _t().lca(4, 5) == 0
def test_lca_self():
    assert _t().lca(2, 5) == 2
def test_kth():
    assert _t().kth_ancestor(4, 1) == 1
