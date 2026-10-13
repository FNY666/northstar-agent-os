"""Input defense 14 tests."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
mod = _load("input_defense_14")


def test_remove_zero_width_space():
    cleaned, removed = mod.remove("a​b")
    assert cleaned == "ab"
    assert removed == 1


def test_remove_multiple_invisible_chars():
    cleaned, removed = mod.remove("a‍­b")
    assert cleaned == "ab"
    assert removed == 2


def test_remove_rejoins_split_keyword():
    cleaned, removed = mod.remove("pas​s⁢wo⁣rd")
    assert cleaned == "password"
    assert removed == 3


def test_has_invisible():
    assert mod.has_invisible("a​b") is True
    assert mod.has_invisible("﻿bom") is True
    assert mod.has_invisible("clean") is False
    assert mod.has_invisible("") is False


def test_clean_input_unchanged():
    assert mod.remove("clean") == ("clean", 0)


def test_non_str_raises():
    for bad in (None, 123, b"clean", ["clean"]):
        try:
            mod.remove(bad)
        except mod.InputDefense14Error:
            pass
        else:
            raise AssertionError("remove(%r) did not raise" % (bad,))
        try:
            mod.has_invisible(bad)
        except mod.InputDefense14Error:
            pass
        else:
            raise AssertionError("has_invisible(%r) did not raise" % (bad,))


def test_stdlib_only():
    assert mod.stdlib_only() is True
