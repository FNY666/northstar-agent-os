"""Tests for runtime_defense_14 (cert pinning)."""
import importlib.util, sys, base64
from pathlib import Path
import pytest
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
d = _load("runtime_defense_14")
PIN_A = base64.b64encode(b"A" * 32).decode()
PIN_C = base64.b64encode(b"C" * 32).decode()
def test_match():
    s = d.build_store({"api.example.com": [PIN_A]})
    ok, _ = s.verify("api.example.com", PIN_A)
    assert ok is True
def test_mismatch():
    s = d.build_store({"api.example.com": [PIN_A]})
    ok, reason = s.verify("api.example.com", PIN_C)
    assert ok is False and "mismatch" in reason
def test_unknown_host_denied():
    s = d.build_store({"api.example.com": [PIN_A]})
    ok, _ = s.verify("other.example.com", PIN_A)
    assert ok is False
def test_deny_all_store():
    s = d.build_store({})
    ok, _ = s.verify("anything.example", PIN_A)
    assert ok is False
def test_bad_pin_raises():
    with pytest.raises(d.PinningError):
        d.build_store({"h.example": ["short"]})
def test_empty_pins_raises():
    with pytest.raises(d.PinningError):
        d.build_store({"h.example": []})
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_14_VERSION == "runtime-defense-14.v1"
