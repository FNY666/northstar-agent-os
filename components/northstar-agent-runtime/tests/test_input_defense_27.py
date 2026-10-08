"""Tests for input_defense_27."""
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


mod = _load("input_defense_27")

def test_values():
    a = mod.Allowlist(values={"a", "b"})
    assert a.check("a") is True
    assert a.check("c") is False


def test_patterns():
    a = mod.Allowlist(patterns=[r"user_\d+"])
    assert a.check("user_42") is True
    assert a.check("user_x") is False


def test_non_str():
    a = mod.Allowlist(values={"a"})
    assert a.check(None) is False


def test_require():
    a = mod.Allowlist(values={"ok"})
    assert a.require("ok") is True
    try:
        a.require("bad")
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_empty_rejected():
    try:
        mod.Allowlist()
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_stdlib_only():
    assert mod.stdlib_only() is True

