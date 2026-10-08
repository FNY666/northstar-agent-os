"""Tests for tree_48 (T-tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_48")
def test_inorder():
    tr = t.TTreeMock()
    for k in [3, 1, 2]: tr.insert(k)
    assert tr.inorder() == [1, 2, 3]
def test_search():
    tr = t.TTreeMock()
    tr.insert(5)
    assert tr.search(5) and not tr.search(4)
def test_many():
    tr = t.TTreeMock()
    for k in range(20): tr.insert(k)
    assert tr.inorder() == list(range(20))
def test_empty():
    assert t.TTreeMock().inorder() == []
