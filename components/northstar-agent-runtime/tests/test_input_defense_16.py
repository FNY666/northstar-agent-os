"""Tests for input_defense_16."""
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


mod = _load("input_defense_16")

def test_strip():
    clean, n = mod.strip_bidi_controls("a\u202eb\u202c")
    assert clean == "ab"
    assert n == 2


def test_all_ranges():
    for cp in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)):
        assert mod.contains_bidi_controls(chr(cp)) is True


def test_clean_unchanged():
    clean, n = mod.strip_bidi_controls("hello world")
    assert clean == "hello world"
    assert n == 0


def test_rejects_non_str():
    try:
        mod.strip_bidi_controls(123)
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_stdlib_only():
    assert mod.stdlib_only() is True

