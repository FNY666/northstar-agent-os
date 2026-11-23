"""Tests for runtime_defense_02 (apparmor)."""
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
d = _load("runtime_defense_02")
def test_minimal_profile():
    p = d.generate_profile("agent", "minimal")
    text = p.render()
    assert "profile agent" in text and "enforce" in text
def test_shadow_denied():
    p = d.generate_profile("agent", "minimal")
    assert "deny /etc/shadow" in p.render()
def test_standard_tmp():
    p = d.generate_profile("agent", "standard")
    assert "/tmp/agent-*/**" in p.render()
def test_unknown_level_raises():
    with pytest.raises(d.ApparmorError):
        d.generate_profile("agent", "bogus")
def test_empty_name_raises():
    with pytest.raises(d.ApparmorError):
        d.generate_profile("", "minimal")
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_02_VERSION == "runtime-defense-02.v1"
