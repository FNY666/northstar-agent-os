"""Tests for proto_41 (Arrow (mock))."""

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


m = _load("proto_41")

def _arrow(schema=b"S"):
    import struct as st
    return b"ARROW1" + st.pack("<I", len(schema)) + schema + b"ARROW1"


def test_schema():
    assert m.parse_arrow(_arrow(b"abc"))["schema"] == b"abc"


def test_bad_magic():
    with pytest.raises(m.Proto41Error):
        m.parse_arrow(b"BAD!!1" + b"\x00" * 10)


def test_schema_len_out_of_range():
    import struct as st
    with pytest.raises(m.Proto41Error):
        m.parse_arrow(b"ARROW1" + st.pack("<I", 999) + b"ARROW1")


def test_stdlib_only():
    assert m.stdlib_only() is True

