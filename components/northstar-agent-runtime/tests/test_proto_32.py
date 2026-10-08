"""Tests for proto_32 (MQTT (mock))."""

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


m = _load("proto_32")

def _connect():
    import struct as st
    body = st.pack("!H", 4) + b"MQTT" + bytes([5, 0]) + st.pack("!H", 30)
    return bytes([0x10, len(body)]) + body


def test_connect():
    c = m.parse_connect(_connect())
    assert c["level"] == 5 and c["keepalive"] == 30


def test_header_type():
    h = m.parse_fixed_header(bytes([0x30, 0x00]))
    assert h["type"] == "PUBLISH"


def test_bad_type():
    with pytest.raises(m.Proto32Error):
        m.parse_fixed_header(bytes([0x00, 0x00]))


def test_bad_protocol_name():
    import struct as st
    body = st.pack("!H", 4) + b"XXXX" + bytes([4, 0]) + st.pack("!H", 0)
    with pytest.raises(m.Proto32Error):
        m.parse_connect(bytes([0x10, len(body)]) + body)


def test_stdlib_only():
    assert m.stdlib_only() is True

