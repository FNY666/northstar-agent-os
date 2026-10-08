"""DS tests: M-Tree (ds_46)."""
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


m = _load("ds_46")


def _tree():
    t = m.MTree(lambda a, b: abs(a - b))
    for v in (3, 9, 15):
        t.insert(v)
    return t


def test_range():
    assert sorted(_tree().range_query(10, 6)) == [9, 15]


def test_no_hits():
    assert _tree().range_query(100, 1) == []


def test_bad_radius():
    try:
        _tree().range_query(0, -2)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
