
"""Tests for state_mgmt_09."""
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
m = _load("state_mgmt_09")

def test_reads_v1():
    assert m.read({"format_version": "v1", "seq": 1})["seq"] == 1
def test_reads_v2():
    s = m.read({"format_version": "v2", "seq": 2, "policy_version": "p"})
    assert s["policy_version"] == "p"
def test_unknown_version():
    with pytest.raises(m.CompatError):
        m.read({"format_version": "v7", "seq": 1})
def test_stdlib():
    assert m.stdlib_only()
