"""DS tests: Stack (ds_05)."""
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


m = _load("ds_05")


def test_lifo():
    s = m.Stack()
    s.push(1); s.push(2); s.push(3)
    assert [s.pop(), s.pop(), s.pop()] == [3, 2, 1]


def test_peek():
    s = m.Stack()
    s.push("x")
    assert s.peek() == "x"
    assert len(s) == 1


def test_is_empty():
    s = m.Stack()
    assert s.is_empty() is True
    s.push(1)
    assert s.is_empty() is False


def test_pop_empty():
    s = m.Stack()
    try:
        s.pop()
    except IndexError:
        pass
    else:
        raise AssertionError("expected IndexError")
