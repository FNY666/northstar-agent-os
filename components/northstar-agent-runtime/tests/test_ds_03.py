"""DS tests: Doubly Linked List (ds_03)."""
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


m = _load("ds_03")


def test_push_both_ends():
    dl = m.DoublyLinkedList()
    dl.push_front(2); dl.push_front(1); dl.push_back(3)
    assert dl.to_list() == [1, 2, 3]


def test_pop_both_ends():
    dl = m.DoublyLinkedList()
    dl.push_back(1); dl.push_back(2)
    assert dl.pop_back() == 2
    assert dl.pop_front() == 1
    assert len(dl) == 0


def test_reverse_walk():
    dl = m.DoublyLinkedList()
    for v in (1, 2, 3):
        dl.push_back(v)
    assert dl.to_list_rev() == [3, 2, 1]


def test_empty_pops():
    dl = m.DoublyLinkedList()
    for op in (dl.pop_front, dl.pop_back):
        try:
            op()
        except IndexError:
            pass
        else:
            raise AssertionError("expected IndexError")
