"""Tests for runtime_defense_11 (dns filter)."""
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
d = _load("runtime_defense_11")
def test_blocklisted():
    f = d.build_filter(["malware.example"])
    ok, _ = f.check("malware.example")
    assert ok is False
def test_subdomain_blocked():
    f = d.build_filter(["malware.example"])
    ok, _ = f.check("sub.malware.example")
    assert ok is False
def test_dga_blocked():
    f = d.build_filter([])
    ok, reason = f.check("xkqzpvtnbmwlrqjd.example.com")
    assert ok is False and "DGA" in reason
def test_dga_off():
    f = d.build_filter([], block_dga=False)
    ok, _ = f.check("xkqzpvtnbmwlrqjd.example.com")
    assert ok is True
def test_empty_query_blocked():
    f = d.build_filter([])
    ok, _ = f.check("")
    assert ok is False
def test_empty_entry_raises():
    with pytest.raises(d.DnsFilterError):
        d.build_filter([""])
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_11_VERSION == "runtime-defense-11.v1"
