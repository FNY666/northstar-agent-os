
"""Tests for state_mgmt_10."""
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
m = _load("state_mgmt_10")

def test_ignores_unknown():
    k, d = m.read({"seq": 1, "zzz": 2})
    assert k == {"seq": 1} and d == ["zzz"]
def test_strict_known():
    with pytest.raises(m.ForwardCompatError):
        m.read({"seq": "one"})
def test_missing_seq():
    with pytest.raises(m.ForwardCompatError):
        m.read({"tool": "x"})
def test_stdlib():
    assert m.stdlib_only()
