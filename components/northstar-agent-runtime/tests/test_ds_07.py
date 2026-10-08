"""DS tests: Deque (ds_07)."""
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


m = _load("ds_07")


def test_both_ends():
    d = m.Deque()
    d.push_back(2); d.push_front(1); d.push_back(3)
    assert d.pop_front() == 1
    assert d.pop_back() == 3
    assert d.pop_front() == 2


def test_peek():
    d = m.Deque()
    d.push_back(9)
    assert d.peek_front() == 9
    assert d.peek_back() == 9


def test_empty_errors():
    d = m.Deque()
    for op in (d.pop_front, d.pop_back, d.peek_front, d.peek_back):
        try:
            op()
        except IndexError:
            pass
        else:
            raise AssertionError("expected IndexError")
