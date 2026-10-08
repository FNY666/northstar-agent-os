"""Tests for proto_16 (CRL (mock))."""

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


m = _load("proto_16")

def _crl():
    return "CRL\nissuer: CN=CA\nthis_update: 2026-02-01\nrevoked: 1, 2\n"


def test_revoked_list():
    assert m.parse_crl(_crl())["revoked"] == ["1", "2"]


def test_is_revoked():
    assert m.is_revoked(_crl(), "2") is True
    assert m.is_revoked(_crl(), "3") is False


def test_empty_revoked():
    c = m.parse_crl("CRL\nissuer: CN=CA\nthis_update: 2026-02-01\n")
    assert c["revoked"] == []


def test_missing_issuer():
    with pytest.raises(m.Proto16Error):
        m.parse_crl("CRL\nthis_update: 2026-02-01\n")


def test_stdlib_only():
    assert m.stdlib_only() is True

