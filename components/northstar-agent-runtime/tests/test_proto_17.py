"""Tests for proto_17 (OCSP (mock))."""

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


m = _load("proto_17")

def test_request():
    assert m.parse_ocsp_request("OCSP-REQ\nserial: 9\n") == {"serial": "9"}


def test_response_statuses():
    for s in ("good", "revoked", "unknown"):
        assert m.parse_ocsp_response("OCSP-RESP\nstatus: %s\n" % s)["status"] == s


def test_bad_status_rejected():
    with pytest.raises(m.Proto17Error):
        m.parse_ocsp_response("OCSP-RESP\nstatus: maybe\n")


def test_revoked_fails_validation():
    ok, reason = m.validate_ocsp_response("OCSP-RESP\nstatus: revoked\n")
    assert ok is False


def test_stdlib_only():
    assert m.stdlib_only() is True

