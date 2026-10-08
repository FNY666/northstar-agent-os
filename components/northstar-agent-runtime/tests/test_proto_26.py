"""Tests for proto_26 (TLS (mock))."""

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


m = _load("proto_26")

def test_handshake():
    import struct as st
    p = m.parse_record(st.pack("!BBBH", 22, 3, 1, 2) + b"hi")
    assert p["type"] == "handshake" and p["fragment"] == b"hi"


def test_alert():
    import struct as st
    p = m.parse_record(st.pack("!BBBH", 21, 3, 3, 0))
    assert p["type"] == "alert" and p["length"] == 0


def test_bad_type():
    import struct as st
    with pytest.raises(m.Proto26Error):
        m.parse_record(st.pack("!BBBH", 30, 3, 3, 0))


def test_truncated():
    import struct as st
    ok, _ = m.validate_record(st.pack("!BBBH", 23, 3, 3, 10) + b"short")
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

