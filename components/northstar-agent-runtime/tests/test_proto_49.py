"""Tests for proto_49 (Smile (mock))."""

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


m = _load("proto_49")

def test_values():
    p = m.parse_smile(b":)\n\x00S\x03abc")
    assert p["values"] == ["abc"] and p["version"] == 0


def test_empty_values():
    assert m.parse_smile(b":)\n\x00")["values"] == []


def test_bad_header():
    with pytest.raises(m.Proto49Error):
        m.parse_smile(b"XXX\x00")


def test_bad_marker():
    with pytest.raises(m.Proto49Error):
        m.parse_smile(b":)\n\x00Q")


def test_stdlib_only():
    assert m.stdlib_only() is True

