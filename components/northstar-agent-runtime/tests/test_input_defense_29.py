"""Tests for input_defense_29."""
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


mod = _load("input_defense_29")

def test_to_int():
    assert mod.to_int("42") == 42
    assert mod.to_int(-3) == -3


def test_to_int_rejects():
    for bad in (True, 2.5, "x", "", [1]):
        try:
            mod.to_int(bad)
        except mod.InputDefenseError:
            continue
        raise AssertionError("should raise for %r" % (bad,))


def test_to_float_rejects_nonfinite():
    for bad in ("nan", "inf", float("nan")):
        try:
            mod.to_float(bad)
        except mod.InputDefenseError:
            continue
        raise AssertionError("should raise for %r" % (bad,))


def test_to_nonempty_str():
    assert mod.to_nonempty_str(" a ") == "a"
    try:
        mod.to_nonempty_str("  ")
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_to_bool():
    assert mod.to_bool("true") is True
    assert mod.to_bool("No") is False
    try:
        mod.to_bool("perhaps")
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_stdlib_only():
    assert mod.stdlib_only() is True

