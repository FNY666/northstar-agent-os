"""Tests for proto_48 (UBJSON (mock))."""

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


m = _load("proto_48")

def test_int8():
    assert m.parse_ubjson(b"i\xff") == (-1, 2)


def test_uint8():
    assert m.parse_ubjson(b"U\xff") == (255, 2)


def test_string():
    v, _ = m.parse_ubjson(b"Si\x03abc")
    assert v == "abc"


def test_bad_marker():
    with pytest.raises(m.Proto48Error):
        m.parse_ubjson(b"Q")


def test_stdlib_only():
    assert m.stdlib_only() is True

