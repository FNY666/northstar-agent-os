"""Tests for proto_01 (JSON)."""

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


m = _load("proto_01")

def test_parse_object():
    assert m.parse_json('{"x": 1}') == {"x": 1}


def test_parse_array():
    assert m.parse_json('[1, "a", null]') == [1, "a", None]


def test_invalid_raises():
    with pytest.raises(m.Proto01Error):
        m.parse_json('{"a":')


def test_required_keys():
    ok, _ = m.validate_json('{"a": 1}', ["a"])
    assert ok is True
    ok, reason = m.validate_json('{"a": 1}', ["b"])
    assert ok is False and "missing" in reason


def test_stdlib_only():
    assert m.stdlib_only() is True

