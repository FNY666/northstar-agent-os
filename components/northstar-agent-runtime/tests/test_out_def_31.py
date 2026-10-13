"""Output watermark verification tests."""

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


d31 = _load("out_def_31")

KEY = "unit-test-key"


def test_embed_verify_roundtrip():
    marked = d31.embed_watermark("agent output", KEY)
    assert d31.has_watermark(marked) is True
    ok, reason = d31.verify_watermark(marked, KEY)
    assert ok is True
    assert "ok" in reason


def test_tampered_body_detected():
    marked = d31.embed_watermark("agent output", KEY)
    ok, reason = d31.verify_watermark(marked.replace("output", "OUTPUT"), KEY)
    assert ok is False
    assert "mismatch" in reason


def test_wrong_key_rejected():
    marked = d31.embed_watermark("agent output", KEY)
    ok, _ = d31.verify_watermark(marked, "wrong-key")
    assert ok is False


def test_no_token():
    assert d31.has_watermark("plain text") is False
    ok, reason = d31.verify_watermark("plain text", KEY)
    assert ok is False
    assert "no watermark" in reason


def test_bytes_key_works():
    marked = d31.embed_watermark("agent output", b"bytes-key")
    ok, _ = d31.verify_watermark(marked, b"bytes-key")
    assert ok is True


def test_empty_key_fail_closed():
    try:
        d31.embed_watermark("agent output", "")
    except d31.OutDef31Error:
        pass
    else:
        raise AssertionError("empty key should fail closed")


def test_stdlib_only():
    assert d31.stdlib_only() is True


def test_version_pin():
    assert d31.OUT_DEF_31_VERSION == "out-def-31.v1"
    assert d31.SCHEMA_PIN == "northstar.out-def-31.v1"
