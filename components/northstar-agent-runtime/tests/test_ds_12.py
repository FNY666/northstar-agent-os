"""DS tests: AVL Tree (ds_12)."""
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


m = _load("ds_12")


def test_insert_search():
    t = m.AVLTree()
    t.insert(10, "x")
    assert t.search(10) == "x"
    assert t.search(11) is None


def test_inorder():
    t = m.AVLTree()
    for k in (3, 1, 2):
        t.insert(k)
    assert t.inorder() == [1, 2, 3]


def test_delete():
    t = m.AVLTree()
    t.insert(5)
    assert t.delete(5) is True
    assert t.delete(5) is False
    assert len(t) == 0
