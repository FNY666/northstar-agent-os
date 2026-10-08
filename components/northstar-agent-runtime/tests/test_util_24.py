"""util_24 tests."""

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


m = _load("util_24")

def test_changed_lines():
    assert m.changed_lines("a\nb\n", "a\nc\n") == 2
    assert m.changed_lines("same", "same") == 0


def test_unified_contains_markers():
    d = m.unified("a\n", "b\n")
    assert "-a" in d and "+b" in d


def test_common_prefix():
    assert m.common_prefix("foobar", "foobaz") == "fooba"
    assert m.common_prefix("abc", "xyz") == ""


def test_similarity():
    assert m.similarity("abc", "abc") == 1.0
    assert m.similarity("abc", "xyz") < 0.5


def test_stdlib_only():
    assert m.stdlib_only() is True
