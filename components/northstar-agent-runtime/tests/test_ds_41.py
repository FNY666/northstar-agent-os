"""DS tests: Range Tree (ds_41)."""
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


m = _load("ds_41")


def test_range_query():
    t = m.RangeTree([1, 5, 3, 9, 7])
    assert t.query(3, 7) == [3, 5, 7]


def test_insert_keeps_sorted():
    t = m.RangeTree()
    t.insert(5); t.insert(2); t.insert(8)
    assert t.query(0, 10) == [2, 5, 8]


def test_empty_result():
    t = m.RangeTree([1, 2, 3])
    assert t.query(10, 20) == []


def test_bad_range():
    t = m.RangeTree([1])
    try:
        t.query(5, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
