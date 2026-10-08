"""Tests for proto_28 (QUIC (mock))."""

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


m = _load("proto_28")

def test_long_header():
    import struct as st
    data = bytes([0x80]) + st.pack("!I", 0xFF00001D) + bytes([1]) + b"A" + bytes([1]) + b"B"
    p = m.parse_quic(data)
    assert p["version"] == 0xFF00001D and p["scid"] == b"B".hex()


def test_short_header():
    p = m.parse_quic(bytes([0x43]) + b"\x01\x02")
    assert p["form"] == "short" and p["dcid"] == "0102"


def test_empty_rejected():
    with pytest.raises(m.Proto28Error):
        m.parse_quic(b"")


def test_truncated_long():
    with pytest.raises(m.Proto28Error):
        m.parse_quic(bytes([0xC0, 0x00]))


def test_stdlib_only():
    assert m.stdlib_only() is True

