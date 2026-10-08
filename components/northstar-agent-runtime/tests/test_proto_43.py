"""Tests for proto_43 (Cap'n Proto (mock))."""

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


m = _load("proto_43")

def test_two_segments():
    import struct as st
    p = m.parse_segment_table(st.pack("<III", 1, 4, 8))
    assert p["segments"] == 2 and p["lengths_words"] == [4, 8]


def test_one_segment():
    import struct as st
    assert m.parse_segment_table(st.pack("<II", 0, 3))["segments"] == 1


def test_truncated():
    import struct as st
    with pytest.raises(m.Proto43Error):
        m.parse_segment_table(st.pack("<II", 2, 3))


def test_stdlib_only():
    assert m.stdlib_only() is True

