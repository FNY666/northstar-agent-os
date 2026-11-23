"""Tests for def_extra_17 (CRL checking mock)."""
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


m = _load("def_extra_17")


def _checker():
    checker = m.CRLChecker()
    checker.install(m.CRL("ca-1", 7, 1000.0, 2000.0, {"AA:BB"}))
    return checker


def test_not_revoked_ok():
    ok, _ = _checker().check("ca-1", "EE:FF", now=1500.0)
    assert ok is True


def test_revoked_denied():
    ok, reason = _checker().check("ca-1", "AA:BB", now=1500.0)
    assert ok is False
    assert "revoked" in reason


def test_stale_crl_fail_closed():
    ok, reason = _checker().check("ca-1", "EE:FF", now=9999.0)
    assert ok is False
    assert "stale" in reason


def test_unknown_issuer_fail_closed():
    ok, _ = _checker().check("ca-9", "EE:FF", now=1500.0)
    assert ok is False


def test_version_pin():
    assert m.DEF_EXTRA_17_VERSION == "def-extra-17.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-17.v1"
