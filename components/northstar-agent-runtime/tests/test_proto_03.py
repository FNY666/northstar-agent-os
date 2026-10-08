"""Tests for proto_03 (TOML (mock))."""

import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("proto_03")

def test_sections():
    doc = m.parse_toml("[a]\nx = 1\n[b]\ny = 2\n")
    assert doc == {"a": {"x": 1}, "b": {"y": 2}}


def test_types():
    doc = m.parse_toml('s = "hi"\ni = 3\nf = 1.5\nb = false\n')
    assert doc == {"s": "hi", "i": 3, "f": 1.5, "b": False}


def test_array():
    doc = m.parse_toml("a = [1, 2]\n")
    assert doc == {"a": [1, 2]}


def test_missing_equals_rejected():
    ok, reason = m.validate_toml("just words\n")
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

