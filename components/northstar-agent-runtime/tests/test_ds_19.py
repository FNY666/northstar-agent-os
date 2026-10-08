"""DS tests: Multiset (ds_19)."""
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


m = _load("ds_19")


def test_counts():
    ms = m.Multiset([1, 1, 2])
    assert ms.count(1) == 2
    assert ms.count(3) == 0


def test_add_remove():
    ms = m.Multiset()
    ms.add("x", 3)
    ms.remove("x", 2)
    assert ms.count("x") == 1
    assert ms.total() == 1


def test_remove_too_many():
    ms = m.Multiset(["x"])
    try:
        ms.remove("x", 5)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
