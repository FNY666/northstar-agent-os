"""DS tests: Quadtree (ds_38)."""
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


m = _load("ds_38")


def test_insert_query():
    q = m.QuadTree(0, 0, 10, 10)
    q.insert((1, 1)); q.insert((8, 8))
    assert q.query_range(0, 0, 5, 5) == [(1, 1)]


def test_subdivision():
    q = m.QuadTree(0, 0, 100, 100, capacity=1)
    q.insert((10, 10)); q.insert((90, 90))
    assert q.divided is True
    assert sorted(q.query_range(0, 0, 100, 100)) == [(10, 10), (90, 90)]


def test_outside():
    q = m.QuadTree(0, 0, 10, 10)
    assert q.insert((50, 50)) is False


def test_empty_query():
    q = m.QuadTree(0, 0, 10, 10)
    q.insert((1, 1))
    assert q.query_range(5, 5, 2, 2) == []
