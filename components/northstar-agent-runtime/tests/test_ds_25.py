"""DS tests: Splay Tree (ds_25)."""
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


m = _load("ds_25")


def test_insert_search():
    t = m.SplayTree()
    t.insert("a", 1)
    assert t.search("a") == 1


def test_repeated_search():
    t = m.SplayTree()
    t.insert(1, "v")
    assert t.search(1) == "v"
    assert t.search(1) == "v"


def test_delete():
    t = m.SplayTree()
    t.insert(2)
    assert t.delete(2) is True
    assert t.delete(2) is False
