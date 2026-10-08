"""Tests for def_extra_20 (protocol version enforcement)."""
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


m = _load("def_extra_20")

POLICY = m.VersionPolicy("TLS1.2", "TLS1.3")


def test_allowed_version():
    ok, _ = m.enforce("TLS1.3", POLICY)
    assert ok is True


def test_below_floor_rejected():
    ok, detail = m.enforce("TLS1.0", POLICY)
    assert ok is False
    assert "below minimum" in detail


def test_unknown_version_fail_closed():
    ok, _ = m.enforce("QUICv99", POLICY)
    assert ok is False


def test_negotiate_picks_best():
    ok, version, _ = m.negotiate(["TLS1.0", "TLS1.2", "TLS1.3"], POLICY)
    assert ok is True
    assert version == "TLS1.3"


def test_negotiate_no_overlap_fail_closed():
    ok, _, detail = m.negotiate(["TLS1.0", "TLS1.1"], POLICY)
    assert ok is False
    assert "no mutually acceptable" in detail


def test_inverted_policy_rejected():
    with pytest.raises(m.VersionPolicyError):
        m.VersionPolicy("TLS1.3", "TLS1.2")


def test_version_pin():
    assert m.DEF_EXTRA_20_VERSION == "def-extra-20.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-20.v1"
