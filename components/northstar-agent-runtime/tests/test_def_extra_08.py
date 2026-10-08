"""Tests for def_extra_08 (transaction signing mock)."""
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


m = _load("def_extra_08")


def test_sign_verify_ok():
    signer = m.TxnSigner(b"txn-key")
    signed = signer.sign({"a": 1}, "n-1")
    ok, reason = signer.verify(signed)
    assert ok is True, reason


def test_tampered_tx_rejected():
    signer = m.TxnSigner(b"txn-key")
    signed = signer.sign({"a": 1}, "n-1")
    bad = m.SignedTxn({"a": 999}, "n-1", signed.signature)
    ok, _ = signer.verify(bad)
    assert ok is False


def test_unknown_nonce_fail_closed():
    signer = m.TxnSigner(b"txn-key")
    signed = signer.sign({"a": 1}, "n-1")
    bad = m.SignedTxn({"a": 1}, "n-9", signed.signature)
    ok, _ = signer.verify(bad)
    assert ok is False


def test_nonce_reuse_rejected():
    signer = m.TxnSigner(b"txn-key")
    signer.sign({"a": 1}, "n-1")
    with pytest.raises(m.TxnSigningError):
        signer.sign({"a": 2}, "n-1")


def test_version_pin():
    assert m.DEF_EXTRA_08_VERSION == "def-extra-08.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-08.v1"
