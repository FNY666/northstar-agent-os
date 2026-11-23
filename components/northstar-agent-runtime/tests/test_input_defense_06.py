"""Input defense 06 tests."""
import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


mod = _load("input_defense_06")


def test_strip_controls_basic():
    cleaned, removed = mod.strip_controls("a\x00b\x07c\x7fd")
    assert cleaned == "abcd"
    assert removed == 3


def test_strip_controls_keeps_default():
    cleaned, removed = mod.strip_controls("line1\nline2\tend\r")
    assert cleaned == "line1\nline2\tend"
    assert removed == 1  # \r stripped


def test_strip_controls_custom_keep():
    cleaned, removed = mod.strip_controls("a\rb", keep=("\r",))
    assert cleaned == "a\rb"
    assert removed == 0


def test_has_controls():
    assert mod.has_controls("x\x00") is True
    assert mod.has_controls("x\x7f") is True
    assert mod.has_controls("ok\n\t") is False


def test_non_str_raises():
    for bad in (123, None, b"x", ["x"]):
        try:
            mod.strip_controls(bad)
        except mod.InputDefense06Error:
            pass
        else:
            raise AssertionError(f"strip_controls({bad!r}) must raise")
        try:
            mod.has_controls(bad)
        except mod.InputDefense06Error:
            pass
        else:
            raise AssertionError(f"has_controls({bad!r}) must raise")
