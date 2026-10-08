"""Tests for tree_43 (K-ary tree)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_43")
def test_bfs():
    k = t.KaryTree(2)
    for v in [1, 2, 3]: k.insert(v)
    assert k.bfs() == [1, 2, 3]
def test_height():
    k = t.KaryTree(2)
    for v in range(4): k.insert(v)
    assert k.height() == 3
def test_empty():
    assert t.KaryTree(3).bfs() == []
def test_k3():
    k = t.KaryTree(3)
    for v in range(5): k.insert(v)
    assert k.height() == 3
