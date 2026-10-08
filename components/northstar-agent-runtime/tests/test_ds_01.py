"""DS tests: Dynamic Array (ds_01)."""
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


m = _load("ds_01")


def test_append_get():
    a = m.DynamicArray()
    a.append(10)
    assert a.get(0) == 10


def test_set():
    a = m.DynamicArray()
    a.append(1)
    a.set(0, 2)
    assert a.get(0) == 2


def test_insert_remove():
    a = m.DynamicArray()
    a.append(1); a.append(3)
    a.insert(1, 2)
    assert a.to_list() == [1, 2, 3]
    assert a.remove(1) == 2
    assert len(a) == 2


def test_index_error():
    a = m.DynamicArray()
    for op in (lambda: a.get(0), lambda: a.set(0, 1), lambda: a.remove(0)):
        try:
            op()
        except IndexError:
            pass
        else:
            raise AssertionError("expected IndexError")
