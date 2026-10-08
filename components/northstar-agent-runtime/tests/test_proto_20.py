"""Tests for proto_20 (NTP (mock))."""

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


m = _load("proto_20")

def _pkt(ver=4, mode=3):
    import struct as st
    return st.pack("!BBbbIIIQQQQ", (ver << 3) | mode, 1, 4, -18, 0, 0, 0, 0, 0, 0, 9)


def test_fields():
    p = m.parse_ntp(_pkt())
    assert (p["version"], p["mode"], p["stratum"]) == (4, 3, 1)
    assert p["tx_timestamp"] == 9


def test_bad_version():
    with pytest.raises(m.Proto20Error):
        m.parse_ntp(_pkt(ver=2))


def test_bad_length():
    ok, _ = m.validate_ntp(b"\x00" * 48 + b"\x00")
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

