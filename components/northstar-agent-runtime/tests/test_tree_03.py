"""Tests for tree_03 (Red-Black mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_03")
def test_inorder():
    r = t.RBTree()
    for k in [4, 2, 6]: r.insert(k)
    assert r.inorder() == [2, 4, 6]
def test_root_black():
    r = t.RBTree()
    for k in range(10): r.insert(k)
    assert r.root.color == t.BLACK
def test_no_double_red():
    r = t.RBTree()
    for k in range(15): r.insert(k)
    assert r.no_double_red()
def test_dupe_ignored():
    r = t.RBTree()
    r.insert(1); r.insert(1)
    assert r.inorder() == [1]
