"""Tests for proto_38 (Avro (mock))."""

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


m = _load("proto_38")

def test_zigzag_roundtrip():
    for n in (0, 1, -1, 300, -300, 2 ** 40):
        v, _ = m.decode_zigzag(m.encode_zigzag(n))
        assert v == n


def test_schema():
    assert m.parse_schema('{"type": "string"}')["type"] == "string"


def test_bad_schema():
    with pytest.raises(m.Proto38Error):
        m.parse_schema('{"type": "record"}')


def test_datum():
    ok, _ = m.validate_datum("boolean", True)
    assert ok is True
    ok, _ = m.validate_datum("boolean", 1)
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

