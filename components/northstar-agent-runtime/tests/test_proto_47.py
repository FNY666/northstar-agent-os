"""Tests for proto_47 (CBOR (mock))."""

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


m = _load("proto_47")

def test_uint():
    assert m.parse_cbor(bytes([0x0A])) == (10, 1)


def test_negint():
    assert m.parse_cbor(bytes([0x22])) == (-3, 1)


def test_text_two_byte_len():
    assert m.parse_cbor(bytes([0x79, 0x00, 0x02]) + b"hi") == ("hi", 5)


def test_map():
    v, _ = m.parse_cbor(bytes([0xA1, 0x01, 0x02]))
    assert v == {1: 2}


def test_stdlib_only():
    assert m.stdlib_only() is True

