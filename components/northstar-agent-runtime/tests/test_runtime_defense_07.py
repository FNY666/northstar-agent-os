"""Tests for runtime_defense_07 (read-only fs)."""
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
d = _load("runtime_defense_07")
def test_root_readonly():
    cfg = d.build_config()
    assert cfg.root_readonly is True
    assert "/" not in cfg.writable_targets()
def test_tmp_writable():
    cfg = d.build_config()
    assert "/tmp" in cfg.writable_targets()
def test_writable_root_refused():
    bad = d.MountConfig(root_readonly=True, entries=[d.MountEntry("/", "bind", "rw")])
    with pytest.raises(d.MountError):
        bad.validate()
def test_writable_etc_refused():
    bad = d.MountConfig(root_readonly=True, entries=[d.MountEntry("/etc", "bind", "rw")])
    with pytest.raises(d.MountError):
        bad.validate()
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_07_VERSION == "runtime-defense-07.v1"
