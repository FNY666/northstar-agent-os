"""Tests for proto_46 (BSON (mock))."""

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


m = _load("proto_46")

def _doc(*elems):
    import struct as st
    body = b"".join(elems) + b"\x00"
    return st.pack("<i", 4 + len(body)) + body


def test_int32():
    import struct as st
    assert m.parse_bson(_doc(b"\x10" + b"n\x00" + st.pack("<i", -3))) == {"n": -3}


def test_string():
    import struct as st
    s = b"hi\x00"
    assert m.parse_bson(_doc(b"\x02" + b"s\x00" + st.pack("<i", len(s)) + s)) == {"s": "hi"}


def test_bool():
    assert m.parse_bson(_doc(b"\x08" + b"b\x00" + b"\x01")) == {"b": True}


def test_length_mismatch():
    with pytest.raises(m.Proto46Error):
        m.parse_bson(b"\x00\x00\x00\x7F\x00")


def test_stdlib_only():
    assert m.stdlib_only() is True

