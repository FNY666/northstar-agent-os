"""Tests for runtime_defense_04 (namespaces)."""
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
d = _load("runtime_defense_04")
def test_default_isolates():
    cfg = d.build_config()
    assert "pid" in cfg.isolated and "net" in cfg.isolated
def test_clone_flags():
    cfg = d.build_config()
    assert "CLONE_NEWPID" in cfg.clone_flags()
def test_unshare_args():
    cfg = d.build_config({"pid", "mnt"})
    assert "--pid" in cfg.unshare_args() and "--mount" in cfg.unshare_args()
def test_unknown_raises():
    with pytest.raises(d.NamespaceError):
        d.build_config({"bogus"})
def test_empty_raises():
    with pytest.raises(d.NamespaceError):
        d.build_config(set())
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_04_VERSION == "runtime-defense-04.v1"
