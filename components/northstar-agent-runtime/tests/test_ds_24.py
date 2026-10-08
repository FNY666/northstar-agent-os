"""DS tests: Treap (ds_24)."""
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


m = _load("ds_24")


def test_insert_search():
    t = m.Treap()
    t.insert(7, "seven")
    assert t.search(7) == "seven"


def test_inorder():
    t = m.Treap()
    for k in (3, 1, 2):
        t.insert(k)
    assert t.inorder() == [1, 2, 3]


def test_delete():
    t = m.Treap()
    t.insert(1)
    assert t.delete(1) is True
    assert len(t) == 0
