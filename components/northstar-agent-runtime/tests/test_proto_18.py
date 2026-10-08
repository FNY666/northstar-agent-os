"""Tests for proto_18 (DNS (mock))."""

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


m = _load("proto_18")

def test_roundtrip():
    p = m.parse_query(m.encode_query(7, "a.b.c"))
    assert (p["id"], p["name"]) == (7, "a.b.c")


def test_qtype():
    p = m.parse_query(m.encode_query(1, "x.com", qtype=28))
    assert p["qtype"] == 28


def test_truncated_rejected():
    with pytest.raises(m.Proto18Error):
        m.parse_query(b"\x00" * 12)


def test_validate():
    ok, _ = m.validate_query(m.encode_query(1, "h.com"))
    assert ok is True
    ok, _ = m.validate_query(b"")
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

