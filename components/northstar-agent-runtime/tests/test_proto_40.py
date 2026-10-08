"""Tests for proto_40 (ORC (mock))."""

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


m = _load("proto_40")

def test_postscript():
    assert m.parse_orc(b"\x00" * 10 + b"Z" + bytes([1]) + b"ORC")["postscript"] == b"Z"


def test_no_magic():
    with pytest.raises(m.Proto40Error):
        m.parse_orc(b"\x00" * 10)


def test_bad_ps_len():
    with pytest.raises(m.Proto40Error):
        m.parse_orc(b"\x01" + bytes([200]) + b"ORC")


def test_stdlib_only():
    assert m.stdlib_only() is True

