"""Tests for proto_12 (PEM (mock))."""

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


m = _load("proto_12")

def _pem(label, raw=b"x"):
    import base64 as b64
    body = b64.b64encode(raw).decode()
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, body, label)


def test_parse():
    blocks = m.parse_pem(_pem("PRIVATE KEY", b"key"))
    assert blocks[0]["label"] == "PRIVATE KEY"
    assert blocks[0]["der"] == b"key"


def test_label_mismatch():
    import base64 as b64
    body = b64.b64encode(b"x").decode()
    with pytest.raises(m.Proto12Error):
        m.parse_pem("-----BEGIN A-----\n%s\n-----END B-----\n" % body)


def test_no_blocks():
    with pytest.raises(m.Proto12Error):
        m.parse_pem("hello")


def test_validate_count():
    ok, reason = m.validate_pem(_pem("X") + _pem("Y"))
    assert ok is True and "2 blocks" in reason


def test_stdlib_only():
    assert m.stdlib_only() is True

