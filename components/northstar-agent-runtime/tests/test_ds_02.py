"""DS tests: Singly Linked List (ds_02)."""
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


m = _load("ds_02")


def test_push_front_back():
    ll = m.LinkedList()
    ll.push_back(2); ll.push_front(1)
    assert ll.to_list() == [1, 2]


def test_pop_front():
    ll = m.LinkedList()
    ll.push_back(5)
    assert ll.pop_front() == 5
    assert len(ll) == 0


def test_find():
    ll = m.LinkedList()
    ll.push_back("a")
    assert ll.find("a") is True
    assert ll.find("b") is False


def test_pop_empty():
    ll = m.LinkedList()
    try:
        ll.pop_front()
    except IndexError:
        pass
    else:
        raise AssertionError("expected IndexError")
