"""Tests for proto_02 (YAML (mock))."""

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


m = _load("proto_02")

def test_nested_mapping():
    doc = m.parse_yaml("a:\n  b: 1\n")
    assert doc == {"a": {"b": 1}}


def test_list():
    doc = m.parse_yaml("items:\n  - a\n  - b\n")
    assert doc == {"items": ["a", "b"]}


def test_scalars():
    doc = m.parse_yaml("a: 1\nb: 2.5\nc: true\nd: null\ne: hi\n")
    assert doc == {"a": 1, "b": 2.5, "c": True, "d": None, "e": "hi"}


def test_bad_indent_rejected():
    ok, _ = m.validate_yaml("a: 1\n  orphan: x\n")
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

