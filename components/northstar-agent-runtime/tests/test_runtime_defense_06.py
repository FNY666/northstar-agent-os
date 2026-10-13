"""Tests for runtime_defense_06 (capabilities)."""
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
d = _load("runtime_defense_06")
def test_drops_sys_admin():
    cfg = d.build_config()
    assert "CAP_SYS_ADMIN" in cfg.drop
def test_default_keep():
    cfg = d.build_config()
    assert "CAP_AUDIT_WRITE" in cfg.keep
def test_capsh_args():
    cfg = d.build_config()
    assert cfg.capsh_args()[0].startswith("--drop=")
def test_dangerous_keep_refused():
    with pytest.raises(d.CapabilityError):
        d.build_config({"CAP_SYS_ADMIN"})
def test_unknown_cap_refused():
    with pytest.raises(d.CapabilityError):
        d.build_config({"CAP_BOGUS"})
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_06_VERSION == "runtime-defense-06.v1"
