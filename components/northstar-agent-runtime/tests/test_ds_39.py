"""DS tests: Octree (ds_39)."""
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


m = _load("ds_39")


def test_insert_query():
    o = m.Octree(0, 0, 0, 10, 10, 10)
    o.insert((1, 1, 1)); o.insert((8, 8, 8))
    assert o.query_range(0, 0, 0, 5, 5, 5) == [(1, 1, 1)]


def test_subdivision():
    o = m.Octree(0, 0, 0, 100, 100, 100, capacity=1)
    o.insert((10, 10, 10)); o.insert((90, 90, 90))
    assert o.children is not None
    assert len(o.query_range(0, 0, 0, 100, 100, 100)) == 2


def test_outside():
    o = m.Octree(0, 0, 0, 10, 10, 10)
    assert o.insert((50, 50, 50)) is False
