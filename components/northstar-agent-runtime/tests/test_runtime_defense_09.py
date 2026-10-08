"""Tests for runtime_defense_09 (network policy)."""
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
d = _load("runtime_defense_09")
def test_https_allowed():
    pol = d.default_policy()
    ok, _ = pol.check("8.8.8.8", 443)
    assert ok is True
def test_http_denied():
    pol = d.default_policy()
    ok, _ = pol.check("8.8.8.8", 80)
    assert ok is False
def test_rfc1918_denied():
    pol = d.default_policy()
    ok, _ = pol.check("10.1.2.3", 443)
    assert ok is False
def test_metadata_blocked():
    pol = d.default_policy()
    ok, _ = pol.check("169.254.169.254", 80)
    assert ok is False
def test_bad_action_raises():
    with pytest.raises(d.NetPolicyError):
        d.EgressRule("maybe", "0.0.0.0/0")
def test_bad_cidr_raises():
    with pytest.raises(d.NetPolicyError):
        d.EgressRule("allow", "not-a-cidr")
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_09_VERSION == "runtime-defense-09.v1"
