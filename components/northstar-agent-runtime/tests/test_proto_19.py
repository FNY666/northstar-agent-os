"""Tests for proto_19 (DHCP (mock))."""

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


m = _load("proto_19")

def _pkt(opt53=1):
    import struct as st
    return (st.pack("!BBBBI", 1, 1, 6, 0, 0xABCD) + bytes(228)
            + b"\x63\x82\x53\x63" + bytes([53, 1, opt53, 255]))


def test_fields():
    p = m.parse_dhcp(_pkt())
    assert p["op"] == 1 and p["xid"] == 0xABCD


def test_message_type():
    assert m.dhcp_message_type(_pkt(3)) == "REQUEST"
    assert m.dhcp_message_type(_pkt(5)) == "ACK"


def test_bad_cookie():
    import struct as st
    bad = st.pack("!BBBBI", 1, 1, 6, 0, 1) + bytes(232)
    with pytest.raises(m.Proto19Error):
        m.parse_dhcp(bad)


def test_too_short():
    ok, _ = m.validate_dhcp(b"\x00" * 100)
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

