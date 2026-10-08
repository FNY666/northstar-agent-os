"""Tests for proto_25 (SSH (mock))."""

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


m = _load("proto_25")

def test_version():
    assert m.parse_version_line("SSH-2.0-libaudit")["software"] == "libaudit"


def test_bad_version():
    with pytest.raises(m.Proto25Error):
        m.parse_version_line("SSH-1.5-old")


def test_packet():
    import struct as st
    pkt = st.pack("!I", 5) + bytes([2]) + b"hi" + bytes(2)
    p = m.parse_binary_packet(pkt)
    assert p["payload"] == b"hi"


def test_truncated():
    ok, _ = m.validate_binary_packet(b"\x00\x00\x00\x10\x00")
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

