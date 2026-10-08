"""Tests for proto_50 (Ion)."""

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


m = _load("proto_50")

def test_int():
    assert m.parse_ion(b"\xe0\x01\x00\xea\x21\x2a") == [42]


def test_negative_int():
    assert m.parse_ion(b"\xe0\x01\x00\xea\x21\xff") == [-1]


def test_string():
    assert m.parse_ion(b"\xe0\x01\x00\xea\x83abc") == ["abc"]


def test_missing_bvm():
    with pytest.raises(m.Proto50Error):
        m.parse_ion(b"\x21\x05")


def test_stdlib_only():
    assert m.stdlib_only() is True

