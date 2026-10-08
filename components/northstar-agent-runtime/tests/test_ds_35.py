"""DS tests: Top Tree (ds_35)."""
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


m = _load("ds_35")


def test_path():
    t = m.TopTree()
    t.link(1, 2); t.link(2, 3)
    assert t.path(1, 3) == [1, 2, 3]


def test_path_length():
    t = m.TopTree()
    t.link("a", "b"); t.link("b", "c"); t.link("c", "d")
    assert t.path_length("a", "d") == 3


def test_disconnected():
    t = m.TopTree()
    t.link(1, 2)
    try:
        t.path(1, 9)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_self_path():
    t = m.TopTree()
    assert t.path(5, 5) == [5]
