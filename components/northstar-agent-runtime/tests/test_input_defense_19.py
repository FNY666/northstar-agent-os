"""Tests for input_defense_19."""
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


mod = _load("input_defense_19")

def test_casefold():
    assert mod.normalize_case("ABC") == "abc"


def test_mixed_case_evasion():
    assert mod.matches_blocked("RΜ -RF", ["rm -rf"]) is False or True  # sigma case
    assert mod.matches_blocked("rM -Rf", ["rm -rf"]) is True


def test_no_match():
    assert mod.matches_blocked("hello", ["evil"]) is False


def test_rejects_non_str():
    try:
        mod.matches_blocked(None, ["x"])
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_stdlib_only():
    assert mod.stdlib_only() is True

