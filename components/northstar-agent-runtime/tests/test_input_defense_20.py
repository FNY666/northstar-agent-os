"""Tests for input_defense_20."""
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


mod = _load("input_defense_20")

def test_fullwidth():
    assert mod.normalize_punctuation("\uff01") == "!"


def test_quotes():
    assert mod.normalize_punctuation("\u201chello\u201d") == '"hello"'


def test_strip():
    assert mod.strip_punctuation("a!b?c.") == "abc"


def test_rejects_non_str():
    try:
        mod.strip_punctuation(5)
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_stdlib_only():
    assert mod.stdlib_only() is True

