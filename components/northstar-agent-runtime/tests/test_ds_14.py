"""DS tests: B-Tree (ds_14)."""
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


m = _load("ds_14")


def test_order_validation():
    try:
        m.BTree(order=2)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_insert_search():
    t = m.BTree()
    t.insert(1, "one")
    assert t.search(1) == "one"


def test_keys_sorted():
    t = m.BTree()
    for k in (4, 2, 8):
        t.insert(k)
    assert t.keys() == [2, 4, 8]


def test_delete():
    t = m.BTree()
    t.insert(7)
    assert t.delete(7) is True
    assert len(t) == 0
