"""Tests for runtime_defense_10 (domain allowlist)."""
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
d = _load("runtime_defense_10")
def test_exact_match():
    al = d.build_allowlist(["api.example.com"])
    assert al.matches("api.example.com") is True
def test_normalization():
    al = d.build_allowlist(["api.example.com"])
    assert al.matches("API.EXAMPLE.COM.") is True
def test_wildcard():
    al = d.build_allowlist(["*.cdn.net"])
    assert al.matches("a.cdn.net") is True
    assert al.matches("cdn.net") is True
def test_suffix_trick_blocked():
    al = d.build_allowlist(["example.com"])
    assert al.matches("example.com.evil.com") is False
def test_unknown_denied():
    al = d.build_allowlist(["api.example.com"])
    ok, _ = al.check("evil.com")
    assert ok is False
def test_empty_raises():
    with pytest.raises(d.EgressFilterError):
        d.build_allowlist([])
def test_bad_domain_raises():
    with pytest.raises(d.EgressFilterError):
        d.build_allowlist(["bad domain!"])
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_10_VERSION == "runtime-defense-10.v1"
