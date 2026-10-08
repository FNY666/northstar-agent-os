"""DS tests: Binary Search Tree (ds_11)."""
import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("ds_11")


def _bst():
    t = m.BST()
    for k in (5, 3, 7, 2, 4):
        t.insert(k)
    return t


def test_inorder_sorted():
    assert _bst().inorder() == [2, 3, 4, 5, 7]


def test_search():
    t = _bst()
    assert t.search(4) is True
    assert t.search(100) is False


def test_delete_leaf():
    t = _bst()
    assert t.delete(2) is True
    assert t.inorder() == [3, 4, 5, 7]


def test_delete_two_children():
    t = _bst()
    assert t.delete(5) is True
    assert t.inorder() == [2, 3, 4, 7]
    assert t.search(5) is False


def test_delete_missing():
    t = _bst()
    assert t.delete(42) is False
