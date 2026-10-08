"""DS tests: SR-Tree (ds_49)."""
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


m = _load("ds_49")


def test_rect_query():
    t = m.SRTree()
    t.insert("r", (0, 0, 10, 10))
    assert t.query_rect((5, 5, 15, 15)) == ["r"]
    assert t.query_rect((20, 20, 30, 30)) == []


def test_sphere_query():
    t = m.SRTree()
    t.insert("r", (0, 0, 4, 4))
    assert t.query_sphere((2, 2), 1) == ["r"]
    assert t.query_sphere((100, 100), 1) == []


def test_bad_radius():
    t = m.SRTree()
    try:
        t.query_sphere((0, 0), -1)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
