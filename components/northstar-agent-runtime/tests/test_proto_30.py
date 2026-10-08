"""Tests for proto_30 (HTTP/3 (mock))."""

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


m = _load("proto_30")

def test_data_frame():
    p = m.parse_frame(m._write_varint(0) + m._write_varint(2) + b"hi")
    assert p["type"] == 0 and p["payload"] == b"hi"


def test_two_byte_varint():
    raw = m._write_varint(0x1234) + m._write_varint(0) + b""
    assert m.parse_frame(raw)["type"] == 0x1234


def test_truncated_payload():
    with pytest.raises(m.Proto30Error):
        m.parse_frame(m._write_varint(1) + m._write_varint(10) + b"short")


def test_stdlib_only():
    assert m.stdlib_only() is True

