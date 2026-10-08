"""Tests for proto_39 (Parquet (mock))."""

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


m = _load("proto_39")

def _pq(footer=b"F"):
    import struct as st
    return b"PAR1" + b"\x00" * 8 + footer + st.pack("<I", len(footer)) + b"PAR1"


def test_footer():
    assert m.parse_parquet(_pq(b"meta"))["footer"] == b"meta"


def test_bad_leading_magic():
    import struct as st
    with pytest.raises(m.Proto39Error):
        m.parse_parquet(b"XXXX" + b"\x00" * 8 + st.pack("<I", 0) + b"PAR1")


def test_bad_trailing_magic():
    with pytest.raises(m.Proto39Error):
        m.parse_parquet(b"PAR1" + b"\x00" * 12)


def test_stdlib_only():
    assert m.stdlib_only() is True

