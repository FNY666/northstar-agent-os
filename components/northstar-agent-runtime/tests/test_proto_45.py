"""Tests for proto_45 (MessagePack (mock))."""

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


m = _load("proto_45")

def test_fixint():
    assert m.parse_msgpack(bytes([0x7F])) == (127, 1)


def test_negative_fixint():
    assert m.parse_msgpack(bytes([0xFF])) == (-1, 1)


def test_nil_bool():
    assert m.parse_msgpack(bytes([0xC0])) == (None, 1)
    assert m.parse_msgpack(bytes([0xC2])) == (False, 1)


def test_trailing_bytes():
    ok, reason = m.validate_msgpack(bytes([0x01, 0x02]))
    assert ok is False and "trailing" in reason


def test_stdlib_only():
    assert m.stdlib_only() is True

