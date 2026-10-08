"""Tests for def_extra_11 (tamper detection)."""
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


m = _load("def_extra_11")

KEY = b"seal-key"


def test_roundtrip():
    token = m.seal(b"data", KEY)
    ok, payload, _ = m.open_seal(token, KEY)
    assert ok is True
    assert payload == b"data"


def test_tampered_body_detected():
    token = m.seal(b"data", KEY)
    parts = token.split(".")
    bad_body = ("A" if parts[1][0] != "A" else "B") + parts[1][1:]
    ok, _, detail = m.open_seal(f"{parts[0]}.{bad_body}.{parts[2]}", KEY)
    assert ok is False
    assert "tamper" in detail


def test_wrong_key_fail_closed():
    token = m.seal(b"data", KEY)
    ok, _, _ = m.open_seal(token, b"wrong")
    assert ok is False


def test_malformed_fail_closed():
    ok, _, _ = m.open_seal("garbage", KEY)
    assert ok is False


def test_version_pin():
    assert m.DEF_EXTRA_11_VERSION == "def-extra-11.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-11.v1"
