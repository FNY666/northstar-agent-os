"""DS tests: R-Tree (ds_36)."""
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


m = _load("ds_36")


def test_hit():
    rt = m.RTree()
    rt.insert(1, (0, 0, 10, 10))
    assert rt.query((5, 5, 6, 6)) == [1]


def test_miss():
    rt = m.RTree()
    rt.insert(1, (0, 0, 1, 1))
    assert rt.query((5, 5, 6, 6)) == []


def test_touching_edges():
    rt = m.RTree()
    rt.insert(1, (0, 0, 2, 2))
    assert rt.query((2, 2, 4, 4)) == [1]


def test_bad_bounds():
    rt = m.RTree()
    try:
        rt.insert(1, (5, 5, 1, 1))
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
