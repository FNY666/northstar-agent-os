"""Tests for def_extra_14 (digital signature verification mock)."""
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


m = _load("def_extra_14")


def _registry():
    reg = m.KeyRegistry()
    reg.add(m.PubKey("k1", "ed25519", b"pub-1"))
    return reg


def test_verify_ok():
    reg = _registry()
    alg, sig = reg.sign_mock("k1", b"hello")
    ok, reason = reg.verify("k1", b"hello", alg, sig)
    assert ok is True, reason


def test_tampered_message_rejected():
    reg = _registry()
    alg, sig = reg.sign_mock("k1", b"hello")
    ok, _ = reg.verify("k1", b"hellx", alg, sig)
    assert ok is False


def test_unknown_key_fail_closed():
    reg = _registry()
    ok, _ = reg.verify("k9", b"hello", "ed25519", "00")
    assert ok is False


def test_disallowed_algorithm_rejected():
    reg = m.KeyRegistry()
    with pytest.raises(m.SigVerifyError):
        reg.add(m.PubKey("k2", "md5-rsa", b"x"))


def test_version_pin():
    assert m.DEF_EXTRA_14_VERSION == "def-extra-14.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-14.v1"
