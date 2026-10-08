"""DS tests: SS-Tree (ds_48)."""
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


m = _load("ds_48")


def test_contains():
    t = m.SSTree()
    t.insert("a", (0, 0), 10)
    assert t.query_point((6, 8)) == ["a"]


def test_outside():
    t = m.SSTree()
    t.insert("a", (0, 0), 1)
    assert t.query_point((5, 5)) == []


def test_bad_radius():
    t = m.SSTree()
    try:
        t.insert("a", (0, 0), -1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
