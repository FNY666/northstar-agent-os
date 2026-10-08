"""Tests for proto_44 (FlatBuffers (mock))."""

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


m = _load("proto_44")

def _buf():
    import struct as st
    return (st.pack("<HH", 6, 10) + bytes(4) + st.pack("<I", 8)
            + bytes(4) + st.pack("<i", 16))


def test_fields():
    p = m.parse_table(_buf(), offset=8)
    assert p["vtable_len"] == 6 and p["table_len"] == 10


def test_root_out_of_range():
    import struct as st
    with pytest.raises(m.Proto44Error):
        m.parse_table(st.pack("<I", 999))


def test_too_short():
    ok, _ = m.validate_table(b"\x01\x02")
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

