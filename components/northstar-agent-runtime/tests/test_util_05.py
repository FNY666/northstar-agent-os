"""util_05 tests."""

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


m = _load("util_05")

def test_truncate():
    assert m.truncate("hello", 4) == "hel\u2026"
    assert m.truncate("hi", 10) == "hi"


def test_sanitize():
    assert m.sanitize("a\x00b\n") == "ab\n"


def test_slugify():
    assert m.slugify("Hello, World!") == "hello-world"


def test_mask_and_blank():
    assert m.mask("1234567890") == "******7890"
    assert m.is_blank("  ") is True
    assert m.is_blank("x") is False


def test_stdlib_only():
    assert m.stdlib_only() is True
