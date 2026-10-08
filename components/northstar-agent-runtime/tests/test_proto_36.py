"""Tests for proto_36 (gRPC (mock))."""

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


m = _load("proto_36")

def test_parse():
    import struct as st
    p = m.parse_grpc_message(bytes([1]) + st.pack("!I", 2) + b"ab")
    assert p["compressed"] is True and p["payload"] == b"ab"


def test_empty_payload():
    import struct as st
    p = m.parse_grpc_message(bytes([0]) + st.pack("!I", 0))
    assert p["length"] == 0


def test_bad_flag():
    import struct as st
    with pytest.raises(m.Proto36Error):
        m.parse_grpc_message(bytes([7]) + st.pack("!I", 0))


def test_truncated():
    import struct as st
    ok, _ = m.validate_grpc_message(bytes([0]) + st.pack("!I", 5) + b"ab")
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

