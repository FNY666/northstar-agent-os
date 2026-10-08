"""Tests for proto_37 (Thrift (mock))."""

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


m = _load("proto_37")

def test_roundtrip():
    p = m.parse_message(m.encode_message("call", 4, 7))
    assert p == {"type": 4, "name": "call", "seqid": 7}


def test_not_strict():
    with pytest.raises(m.Proto37Error):
        m.parse_message(b"\x00" * 12)


def test_truncated_name():
    import struct as st
    with pytest.raises(m.Proto37Error):
        m.parse_message(st.pack("!i", -2147418112) + st.pack("!i", 100) + b"ab")


def test_stdlib_only():
    assert m.stdlib_only() is True

