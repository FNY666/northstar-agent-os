"""Tests for def_extra_16 (OCSP stapling mock)."""
import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("def_extra_16")


def _responder():
    return m.OCSPResponder(b"ocsp-key")


def test_good_response_ok():
    resp = _responder()
    r = resp.staple("01:23", "good", now=1000.0, validity_s=3600.0)
    ok, reason = resp.check(r, now=2000.0)
    assert ok is True, reason


def test_revoked_rejected():
    resp = _responder()
    r = resp.staple("01:23", "revoked", now=1000.0)
    ok, _ = resp.check(r, now=2000.0)
    assert ok is False


def test_expired_rejected():
    resp = _responder()
    r = resp.staple("01:23", "good", now=1000.0, validity_s=3600.0)
    ok, reason = resp.check(r, now=99999.0)
    assert ok is False
    assert "expired" in reason


def test_tampered_mac_rejected():
    resp = _responder()
    r = resp.staple("01:23", "good", now=1000.0)
    bad = m.OCSPResponse(r.serial, r.status, r.this_update, r.next_update, "00")
    ok, _ = resp.check(bad, now=2000.0)
    assert ok is False


def test_version_pin():
    assert m.DEF_EXTRA_16_VERSION == "def-extra-16.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-16.v1"
