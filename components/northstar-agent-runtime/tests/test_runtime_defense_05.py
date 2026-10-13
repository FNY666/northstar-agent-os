"""Tests for runtime_defense_05 (cgroups)."""
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
d = _load("runtime_defense_05")
def test_default_render():
    lim = d.CgroupLimits()
    r = lim.render()
    assert r["memory.max"] == str(512 * 1024 ** 2)
    assert r["pids.max"] == "128"
def test_memory_bytes():
    assert d.CgroupLimits(memory_max="2G").memory_bytes() == 2 * 1024 ** 3
def test_max_memory():
    lim = d.CgroupLimits(memory_max="max")
    assert lim.memory_bytes() is None
    assert lim.render()["memory.max"] == "max"
def test_bad_memory_raises():
    with pytest.raises(d.CgroupError):
        d.CgroupLimits(memory_max="bogus")
def test_bad_pids_raises():
    with pytest.raises(d.CgroupError):
        d.CgroupLimits(pids_max=0)
def test_bad_cpu_raises():
    with pytest.raises(d.CgroupError):
        d.CgroupLimits(cpu_max="nonsense")
def test_stdlib_only():
    assert d.stdlib_only() is True
def test_version_pin():
    assert d.RUNTIME_DEFENSE_05_VERSION == "runtime-defense-05.v1"
