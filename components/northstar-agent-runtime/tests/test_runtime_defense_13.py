"""Tests for runtime_defense_13 (tls intercept mock)."""
import importlib.util, sys
from pathlib import Path
import pytest
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
d = _load("runtime_defense_13")
def test_intercept_default():
    cfg = d.build_config("ca-2026")
    yes, _ = cfg.should_intercept("api.example.com")
    assert yes is True
def test_exclusion():
    cfg = d.build_config("ca-2026", ["bank.example.com"])
    no, _ = cfg.should_intercept("bank.example.com")
    assert no is False
def test_wildcard_exclusion():
    cfg = d.build_config("ca-2026", ["*.health.example"])
    no, _ = cfg.should_intercept("a.health.example")
    assert no is False
def test_empty_ca_raises():
    with pytest.raises(d.TlsInterceptError):
        d.build_config("")
def test_bad_tls_version_raises():
    with pytest.raises(d.TlsInterceptError):
        d.TlsInterceptConfig(ca_name="x", min_tls_version="0.9")
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_13_VERSION == "runtime-defense-13.v1"
