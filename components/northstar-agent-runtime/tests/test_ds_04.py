"""DS tests: Circular Linked List (ds_04)."""
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


m = _load("ds_04")


def test_wraps_around():
    cl = m.CircularList()
    cl.append("a"); cl.append("b")
    assert cl.iterate(5) == ["a", "b", "a", "b", "a"]


def test_remove_head():
    cl = m.CircularList()
    cl.append(1); cl.append(2); cl.append(3)
    assert cl.remove(1) is True
    assert cl.iterate(3) == [2, 3, 2]


def test_remove_missing():
    cl = m.CircularList()
    cl.append(1)
    assert cl.remove(2) is False
    assert len(cl) == 1


def test_singleton():
    cl = m.CircularList()
    cl.append(7)
    assert cl.iterate(3) == [7, 7, 7]
    assert cl.remove(7) is True
    assert len(cl) == 0
