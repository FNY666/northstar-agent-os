"""DS tests: Fenwick Tree (ds_28)."""
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


m = _load("ds_28")


def test_prefix():
    ft = m.FenwickTree(4)
    ft.add(0, 5); ft.add(3, 7)
    assert ft.prefix(1) == 5
    assert ft.prefix(4) == 12


def test_range_sum():
    ft = m.FenwickTree(5)
    for i in range(5):
        ft.add(i, i + 1)
    assert ft.range_sum(1, 4) == 9


def test_add_twice():
    ft = m.FenwickTree(3)
    ft.add(1, 2); ft.add(1, 3)
    assert ft.prefix(2) == 5


def test_bad_index():
    ft = m.FenwickTree(3)
    try:
        ft.add(3, 1)
    except IndexError:
        pass
    else:
        raise AssertionError("expected IndexError")
