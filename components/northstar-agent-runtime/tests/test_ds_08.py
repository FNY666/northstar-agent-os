"""DS tests: Priority Queue (ds_08)."""
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


m = _load("ds_08")


def test_priority_order():
    pq = m.PriorityQueue()
    pq.push(5, "e"); pq.push(1, "a"); pq.push(3, "c")
    assert [pq.pop(), pq.pop(), pq.pop()] == ["a", "c", "e"]


def test_fifo_tiebreak():
    pq = m.PriorityQueue()
    pq.push(1, "first"); pq.push(1, "second")
    assert pq.pop() == "first"
    assert pq.pop() == "second"


def test_peek_no_remove():
    pq = m.PriorityQueue()
    pq.push(2, "x")
    assert pq.peek() == "x"
    assert len(pq) == 1


def test_pop_empty():
    pq = m.PriorityQueue()
    try:
        pq.pop()
    except IndexError:
        pass
    else:
        raise AssertionError("expected IndexError")
