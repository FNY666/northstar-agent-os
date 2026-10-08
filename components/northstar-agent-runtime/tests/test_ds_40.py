"""DS tests: Interval Tree (ds_40)."""
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


m = _load("ds_40")


def test_point_query():
    t = m.IntervalTree()
    t.insert(0, 10, "x"); t.insert(20, 30, "y")
    assert t.query_point(5) == [(0, 10, "x")]
    assert t.query_point(15) == []


def test_overlap_query():
    t = m.IntervalTree()
    t.insert(1, 3); t.insert(5, 7)
    assert len(t.query_overlap(2, 6)) == 2
    assert t.query_overlap(8, 9) == []


def test_bad_interval():
    t = m.IntervalTree()
    try:
        t.insert(5, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
