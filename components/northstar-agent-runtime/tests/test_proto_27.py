"""Tests for proto_27 (DTLS (mock))."""

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


m = _load("proto_27")

def _rec(ctype=22, epoch=0, seq=1, frag=b"x"):
    import struct as st
    return st.pack("!BBBH6sH", ctype, 254, 253, epoch, seq.to_bytes(6, "big"), len(frag)) + frag


def test_fields():
    p = m.parse_dtls_record(_rec(epoch=2, seq=9, frag=b"hi"))
    assert (p["epoch"], p["sequence"], p["fragment"]) == (2, 9, b"hi")


def test_version():
    p = m.parse_dtls_record(_rec())
    assert p["version"] == (254, 253)


def test_short_rejected():
    with pytest.raises(m.Proto27Error):
        m.parse_dtls_record(b"\x00" * 12)


def test_stdlib_only():
    assert m.stdlib_only() is True

