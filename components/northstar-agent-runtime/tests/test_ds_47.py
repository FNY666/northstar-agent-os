"""DS tests: X-Tree (ds_47)."""
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


m = _load("ds_47")


def test_overlap():
    t = m.XTree()
    t.insert("a", (0, 0, 4, 4))
    assert t.query((2, 2, 6, 6)) == ["a"]


def test_no_overlap():
    t = m.XTree()
    t.insert("a", (0, 0, 1, 1))
    assert t.query((5, 5, 6, 6)) == []


def test_bad_bounds():
    t = m.XTree()
    try:
        t.insert("a", (3, 3, 1, 1))
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
