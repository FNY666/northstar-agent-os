"""util_06 tests."""

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


m = _load("util_06")

def test_deep_merge():
    assert m.deep_merge({"a": {"x": 1}}, {"a": {"y": 2}}) == {"a": {"x": 1, "y": 2}}
    assert m.deep_merge({"a": 1}, {"a": 2}) == {"a": 2}


def test_flatten_roundtrip():
    d = {"a": {"b": 1, "c": {"d": 2}}}
    assert m.unflatten(m.flatten(d)) == d


def test_get_path():
    assert m.get_path({"a": {"b": 1}}, "a.b") == 1
    assert m.get_path({}, "x", default=7) == 7


def test_set_path():
    d = {}
    m.set_path(d, "a.b.c", 3)
    assert d == {"a": {"b": {"c": 3}}}


def test_stdlib_only():
    assert m.stdlib_only() is True
