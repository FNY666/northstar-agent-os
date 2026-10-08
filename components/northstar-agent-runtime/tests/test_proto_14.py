"""Tests for proto_14 (PKCS#7 (mock))."""

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


m = _load("proto_14")

def _env(oid="1.2.840.113549.1.7.1", raw=b"d"):
    import base64 as b64
    return "PKCS7:%s:%s" % (oid, b64.b64encode(raw).decode())


def test_content_types():
    assert m.parse_pkcs7(_env())["content_type"] == "data"
    assert m.parse_pkcs7(_env("1.2.840.113549.1.7.3"))["content_type"] == "envelopedData"


def test_unknown_oid_rejected():
    with pytest.raises(m.Proto14Error):
        m.parse_pkcs7(_env("1.2.3.4"))


def test_bad_envelope():
    ok, _ = m.validate_pkcs7("not an envelope")
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

