"""DS tests: Binary Heap (ds_09)."""
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


m = _load("ds_09")


def test_heapify_and_pop():
    h = m.MinHeap([4, 1, 7, 3])
    assert [h.pop() for _ in range(4)] == [1, 3, 4, 7]


def test_push_peek():
    h = m.MinHeap()
    h.push(9); h.push(2)
    assert h.peek() == 2
    assert len(h) == 2


def test_empty_errors():
    h = m.MinHeap()
    for op in (h.pop, h.peek):
        try:
            op()
        except IndexError:
            pass
        else:
            raise AssertionError("expected IndexError")
