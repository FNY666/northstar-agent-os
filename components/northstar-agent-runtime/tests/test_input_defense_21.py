"""Tests for input_defense_21."""
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


mod = _load("input_defense_21")

def test_ok():
    assert mod.check_length("hello", max_chars=10) is True


def test_too_long():
    try:
        mod.check_length("x" * 11, max_chars=10)
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_too_many_bytes():
    try:
        mod.check_length("\u00e9" * 10, max_bytes=5)
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_truncate():
    assert mod.truncate_for_log("short", 10) == "short"
    assert mod.truncate_for_log("x" * 20, 10).endswith("[truncated]")


def test_stdlib_only():
    assert mod.stdlib_only() is True

