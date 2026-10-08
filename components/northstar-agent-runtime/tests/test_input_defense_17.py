"""Tests for input_defense_17."""
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


mod = _load("input_defense_17")

def test_strip():
    clean, n = mod.strip_zero_width("a\u200bb\u200cc\u200dd\ufeffe")
    assert clean == "abcde"
    assert n == 4


def test_detect():
    assert mod.contains_zero_width("\u200b") is True
    assert mod.contains_zero_width("plain") is False


def test_empty():
    clean, n = mod.strip_zero_width("")
    assert clean == ""
    assert n == 0


def test_rejects_non_str():
    try:
        mod.strip_zero_width(1.5)
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_stdlib_only():
    assert mod.stdlib_only() is True

