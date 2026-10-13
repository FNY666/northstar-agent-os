"""Tests for def_extra_12 (secure timestamping mock)."""
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


m = _load("def_extra_12")


def test_issue_verify_ok():
    tsa = m.TimestampAuthority(b"tsa-key")
    token = tsa.issue("sha256:abc", now=1000.0)
    ok, reason = tsa.verify(token, now=1010.0)
    assert ok is True, reason


def test_tampered_hash_rejected():
    tsa = m.TimestampAuthority(b"tsa-key")
    token = tsa.issue("sha256:abc", now=1000.0)
    bad = m.TimestampToken(token.ts, token.nonce, "sha256:evil", token.mac)
    ok, _ = tsa.verify(bad, now=1010.0)
    assert ok is False


def test_future_stamp_rejected():
    tsa = m.TimestampAuthority(b"tsa-key", max_future_skew_s=60.0)
    token = tsa.issue("sha256:abc", now=1000.0)
    future = m.TimestampToken(
        99999.0, token.nonce, token.data_hash,
        tsa._mac(99999.0, token.nonce, token.data_hash),
    )
    ok, reason = tsa.verify(future, now=1010.0)
    assert ok is False
    assert "future" in reason


def test_version_pin():
    assert m.DEF_EXTRA_12_VERSION == "def-extra-12.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-12.v1"
