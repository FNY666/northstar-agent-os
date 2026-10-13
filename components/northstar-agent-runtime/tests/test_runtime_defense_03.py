"""Tests for runtime_defense_03 (selinux mock)."""
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
d = _load("runtime_defense_03")
def test_allow_tmp_write():
    p = d.generate_policy("p")
    assert p.check("agent_t", "agent_tmp_t", "file", "write") is True
def test_deny_tmp_exec():
    p = d.generate_policy("p")
    assert p.check("agent_t", "agent_tmp_t", "file", "execute") is False
def test_neverallow_shadow():
    p = d.generate_policy("p")
    assert p.check("agent_t", "shadow_t", "file", "read") is False
def test_unknown_denied():
    p = d.generate_policy("p")
    assert p.check("agent_t", "other_t", "file", "read") is False
def test_render_has_neverallow():
    p = d.generate_policy("p")
    assert "neverallow" in p.render()
def test_empty_name_raises():
    with pytest.raises(d.SelinuxError):
        d.generate_policy("")
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_03_VERSION == "runtime-defense-03.v1"
