"""Tests for proto_35 (CoAP (mock))."""

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


m = _load("proto_35")

def test_con():
    import struct as st
    p = m.parse_coap(st.pack("!BBH", 0x40, 2, 7))
    assert p["type"] == "CON" and p["token"] == ""


def test_ack():
    import struct as st
    assert m.parse_coap(st.pack("!BBH", 0x60, 0, 1))["type"] == "ACK"


def test_bad_version():
    import struct as st
    with pytest.raises(m.Proto35Error):
        m.parse_coap(st.pack("!BBH", 0x00, 0, 1))


def test_truncated_token():
    import struct as st
    ok, _ = m.validate_coap(st.pack("!BBH", 0x42, 0, 1) + b"\x01")
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

