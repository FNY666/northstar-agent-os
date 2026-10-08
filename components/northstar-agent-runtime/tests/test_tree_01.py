"""Tests for tree_01 (BST)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_01")
def test_insert_inorder():
    b = t.BST()
    for k in [5, 3, 7]: b.insert(k)
    assert b.inorder() == [3, 5, 7]
def test_search():
    b = t.BST()
    b.insert(1); b.insert(2)
    assert b.search(1) and not b.search(3)
def test_delete():
    b = t.BST()
    for k in [5, 3, 7]: b.insert(k)
    assert b.delete(5) and b.inorder() == [3, 7]
def test_delete_missing():
    b = t.BST()
    assert not b.delete(1)
