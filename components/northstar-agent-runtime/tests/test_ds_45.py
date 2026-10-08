"""DS tests: Ball Tree (ds_45)."""
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


m = _load("ds_45")


def _tree():
    t = m.BallTree(lambda a, b: abs(a - b))
    t.build([2, 8, 14])
    return t


def test_radius():
    assert sorted(_tree().query_radius(9, 3)) == [8]


def test_radius_empty():
    assert _tree().query_radius(100, 1) == []


def test_bad_radius():
    t = _tree()
    try:
        t.query_radius(0, -1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_nearest():
    assert _tree().nearest(13) == 14
