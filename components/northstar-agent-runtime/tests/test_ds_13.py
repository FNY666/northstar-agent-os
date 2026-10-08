"""DS tests: Red-Black Tree (ds_13)."""
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


m = _load("ds_13")


def test_insert_search():
    t = m.RBTree()
    t.insert("k", "v")
    assert t.search("k") == "v"


def test_inorder():
    t = m.RBTree()
    for k in (9, 4, 7):
        t.insert(k)
    assert t.inorder() == [4, 7, 9]


def test_delete_missing():
    t = m.RBTree()
    assert t.delete("nope") is False
