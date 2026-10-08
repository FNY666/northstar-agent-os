"""Tests for proto_13 (DER (mock))."""

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


m = _load("proto_13")

def test_integer():
    assert m.parse_der(b"\x02\x01\x05") == [(0x02, b"\x05")]


def test_long_form_length():
    val = b"v" * 200
    data = b"\x04\x82\x00\xc8" + val
    assert m.parse_der(data) == [(0x04, val)]


def test_truncated_rejected():
    with pytest.raises(m.Proto13Error):
        m.parse_der(b"\x02\x05\x05")


def test_indefinite_rejected():
    with pytest.raises(m.Proto13Error):
        m.parse_der(b"\x30\x80\x00\x00")


def test_tag_name():
    assert m.der_tag_name(0x02) == "INTEGER"
    assert "UNKNOWN" in m.der_tag_name(0xFF)


def test_stdlib_only():
    assert m.stdlib_only() is True

