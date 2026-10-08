"""Tests for proto_11 (JWT (mock))."""

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


m = _load("proto_11")

def _tok(header, payload, sig=b"s"):
    import base64 as b64
    import json as js

    def seg(o):
        return b64.urlsafe_b64encode(js.dumps(o).encode()).rstrip(b"=").decode()

    return seg(header) + "." + seg(payload) + "." + b64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def test_parse():
    h, p, s = m.parse_jwt(_tok({"alg": "HS256", "typ": "JWT"}, {"sub": "u"}))
    assert h["typ"] == "JWT" and p["sub"] == "u" and s == b"s"


def test_two_segments_rejected():
    with pytest.raises(m.Proto11Error):
        m.parse_jwt("a.b")


def test_missing_alg():
    ok, reason = m.validate_jwt(_tok({"typ": "JWT"}, {}))
    assert ok is False and "alg" in reason


def test_empty_signature():
    ok, _ = m.validate_jwt(_tok({"alg": "x", "typ": "y"}, {}, b""))
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

