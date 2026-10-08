"""Tests for input_defense_30."""
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


mod = _load("input_defense_30")

def test_inclusive_bounds():
    assert mod.check_range(0, 0, 10) == 0
    assert mod.check_range(10, 0, 10) == 10


def test_out_of_range():
    for v in (-1, 11):
        try:
            mod.check_range(v, 0, 10)
        except mod.InputDefenseError:
            continue
        raise AssertionError("should raise for %r" % (v,))


def test_rejects_bool_and_str():
    for v in (True, "5"):
        try:
            mod.check_range(v, 0, 10)
        except mod.InputDefenseError:
            continue
        raise AssertionError("should raise for %r" % (v,))


def test_int_range():
    assert mod.check_int_range(4, 0, 10) == 4
    try:
        mod.check_int_range(4.5, 0, 10)
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_in_range_predicate():
    assert mod.in_range(5, 0, 10) is True
    assert mod.in_range(-5, 0, 10) is False


def test_stdlib_only():
    assert mod.stdlib_only() is True

