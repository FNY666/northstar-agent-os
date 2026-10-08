"""DS tests: Queue (ds_06)."""
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


m = _load("ds_06")


def test_fifo():
    q = m.Queue()
    q.enqueue(1); q.enqueue(2); q.enqueue(3)
    assert [q.dequeue(), q.dequeue(), q.dequeue()] == [1, 2, 3]


def test_peek():
    q = m.Queue()
    q.enqueue("a")
    assert q.peek() == "a"
    assert len(q) == 1


def test_is_empty():
    q = m.Queue()
    assert q.is_empty() is True
    q.enqueue(1)
    assert q.is_empty() is False


def test_dequeue_empty():
    q = m.Queue()
    try:
        q.dequeue()
    except IndexError:
        pass
    else:
        raise AssertionError("expected IndexError")
