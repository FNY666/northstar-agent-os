"""Tests for proto_33 (AMQP (mock))."""

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


m = _load("proto_33")

def test_header():
    assert m.parse_protocol_header(b"AMQP\x00\x00\x09\x01extra") == {"ok": True}


def test_bad_header():
    with pytest.raises(m.Proto33Error):
        m.parse_protocol_header(b"AMQP\x00\x00\x09\x00")


def test_frame():
    import struct as st
    f = m.parse_frame(st.pack("!BHI", 8, 0, 0) + bytes([0xCE]))
    assert f["type"] == "heartbeat"


def test_bad_end_octet():
    import struct as st
    with pytest.raises(m.Proto33Error):
        m.parse_frame(st.pack("!BHI", 1, 0, 0) + bytes([0x00]))


def test_stdlib_only():
    assert m.stdlib_only() is True

