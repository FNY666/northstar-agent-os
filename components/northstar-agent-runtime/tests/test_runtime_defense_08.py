"""Tests for runtime_defense_08 (no-new-privs)."""
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
d = _load("runtime_defense_08")
def test_default_enabled_locked():
    cfg = d.build_config()
    assert cfg.enabled is True and cfg.prctl_value() == 1
def test_disable_refused():
    cfg = d.build_config()
    with pytest.raises(d.NoNewPrivsError):
        cfg.disable()
def test_reenable_after_lock_refused():
    cfg = d.build_config()
    with pytest.raises(d.NoNewPrivsError):
        cfg.enable()
def test_enable_then_lock():
    cfg = d.NoNewPrivsConfig(enabled=False)
    cfg.enable()
    assert cfg.enabled is True
    cfg.lock()
    with pytest.raises(d.NoNewPrivsError):
        cfg.enable()
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_08_VERSION == "runtime-defense-08.v1"
