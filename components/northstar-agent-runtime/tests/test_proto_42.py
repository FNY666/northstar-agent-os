"""Tests for proto_42 (Protobuf (mock))."""

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


m = _load("proto_42")

def test_varint_field():
    assert m.parse_fields(bytes([0x08, 0x01])) == [(1, 0, 1)]


def test_len_delimited():
    assert m.parse_fields(bytes([0x12, 0x03]) + b"abc") == [(2, 2, b"abc")]


def test_fixed32():
    assert m.parse_fields(bytes([0x1D]) + b"\x01\x02\x03\x04") == [(3, 5, b"\x01\x02\x03\x04")]


def test_bad_wire_type():
    with pytest.raises(m.Proto42Error):
        m.parse_fields(bytes([0x0B]))


def test_truncated():
    ok, _ = m.validate_fields(bytes([0x08]))
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

