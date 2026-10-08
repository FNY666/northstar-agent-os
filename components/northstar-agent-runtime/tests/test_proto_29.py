"""Tests for proto_29 (HTTP/2 (mock))."""

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


m = _load("proto_29")

def _frame(ftype=6, flags=0, sid=0, payload=b"12345678"):
    import struct as st
    return len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + st.pack("!I", sid) + payload


def test_ping():
    p = m.parse_frame(_frame())
    assert p["type"] == "PING" and p["length"] == 8


def test_stream_id_mask():
    import struct as st
    raw = b"\x00\x00\x00" + bytes([1, 4]) + st.pack("!I", 0x80000005)
    assert m.parse_frame(raw)["stream_id"] == 5


def test_bad_type():
    with pytest.raises(m.Proto29Error):
        m.parse_frame(_frame(ftype=99))


def test_truncated():
    ok, _ = m.validate_frame(_frame(payload=b"hi")[:10])
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

