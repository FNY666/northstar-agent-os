"""DS tests: Bitset (ds_21)."""
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


m = _load("ds_21")


def test_set_test():
    b = m.Bitset(16)
    b.set(5)
    assert b.test(5) is True
    assert b.test(6) is False


def test_clear():
    b = m.Bitset(16)
    b.set(2); b.clear(2)
    assert b.test(2) is False


def test_count():
    b = m.Bitset(8)
    b.set(0); b.set(3); b.set(7)
    assert b.count() == 3


def test_bounds():
    b = m.Bitset(4)
    for op in (lambda: b.set(4), lambda: b.test(-1)):
        try:
            op()
        except IndexError:
            pass
        else:
            raise AssertionError("expected IndexError")
