"""Tests for proto_31 (WebSocket (mock))."""

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


m = _load("proto_31")

def test_text_frame():
    p = m.parse_frame(bytes([0x81, 0x02]) + b"hi")
    assert p["opcode"] == "text" and p["payload"] == b"hi"


def test_ping():
    p = m.parse_frame(bytes([0x89, 0x00]))
    assert p["opcode"] == "ping" and p["fin"] is True


def test_bad_opcode():
    with pytest.raises(m.Proto31Error):
        m.parse_frame(bytes([0x87, 0x00]))


def test_rsv_rejected():
    with pytest.raises(m.Proto31Error):
        m.parse_frame(bytes([0x91, 0x00]))


def test_stdlib_only():
    assert m.stdlib_only() is True

