"""DS tests: Skip List (ds_23)."""
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


m = _load("ds_23")


def test_ordered_keys():
    s = m.SkipList()
    for k in (5, 1, 4):
        s.insert(k)
    assert s.keys() == [1, 4, 5]


def test_search():
    s = m.SkipList()
    s.insert("k", "v")
    assert s.search("k") == "v"
    assert s.search("missing") is None


def test_delete():
    s = m.SkipList()
    s.insert(1)
    assert s.delete(1) is True
    assert s.delete(1) is False
    assert len(s) == 0
