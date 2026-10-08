"""DS tests: Bag (ds_20)."""
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


m = _load("ds_20")


def test_add_count():
    b = m.Bag()
    b.add(1); b.add(1)
    assert b.count(1) == 2
    assert b.count(2) == 0


def test_remove():
    b = m.Bag()
    b.add("a")
    b.remove("a")
    assert b.count("a") == 0


def test_remove_absent():
    b = m.Bag()
    try:
        b.remove("nope")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_totals():
    b = m.Bag()
    b.add(1); b.add(1); b.add(2)
    assert b.distinct() == 2
    assert b.total() == 3
