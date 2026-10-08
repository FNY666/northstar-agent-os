"""Tests for runtime_defense_01 (seccomp)."""
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
d = _load("runtime_defense_01")
def test_minimal_no_network():
    p = d.generate_profile("minimal")
    assert d.is_allowed(p, "read") is True
    assert d.is_allowed(p, "socket") is False
def test_standard_has_network():
    p = d.generate_profile("standard")
    assert d.is_allowed(p, "socket") is True
    assert d.is_allowed(p, "execve") is False
def test_permissive_has_exec():
    p = d.generate_profile("permissive")
    assert d.is_allowed(p, "execve") is True
def test_strictness_ordering():
    a = d.generate_profile("minimal")
    b = d.generate_profile("standard")
    c = d.generate_profile("permissive")
    assert len(a.allowlist) < len(b.allowlist) < len(c.allowlist)
def test_unknown_level_raises():
    with pytest.raises(d.SeccompError):
        d.generate_profile("bogus")
def test_json_renders():
    import json
    p = d.generate_profile("minimal")
    parsed = json.loads(p.to_json())
    assert parsed["defaultAction"] == "SCMP_ACT_ERRNO"
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_01_VERSION == "runtime-defense-01.v1"
