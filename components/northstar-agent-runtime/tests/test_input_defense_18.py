"""Tests for input_defense_18."""
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


mod = _load("input_defense_18")

def test_normalize():
    assert mod.normalize_whitespace("  a   b  ") == "a b"


def test_tabs_newlines():
    assert mod.normalize_whitespace("a\t\n b") == "a b"


def test_anomaly():
    assert mod.whitespace_anomaly("x" + " " * 100) is True
    assert mod.whitespace_anomaly("x y") is False


def test_rejects_non_str():
    try:
        mod.normalize_whitespace(["x"])
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_stdlib_only():
    assert mod.stdlib_only() is True

