"""Tests for state_mgmt_28."""
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
m = _load("state_mgmt_28")

def test_lww_value():
    a, b = m.LWWMap(), m.LWWMap()
    a.put("k", "A", 1, "n1"); b.put("k", "B", 2, "n2")
    a.merge(b)
    assert a.get("k") == "B"
def test_remove():
    x = m.LWWMap()
    x.put("k", "v", 1, "n"); x.remove("k", 2, "n")
    assert "k" not in x
def test_resurrect():
    x = m.LWWMap()
    x.put("k", "v", 1, "n"); x.remove("k", 2, "n"); x.put("k", "w", 3, "n")
    assert x.get("k") == "w"
def test_empty_key():
    with pytest.raises(m.LWWMapError):
        m.LWWMap().put("", "v", 1, "n")
def test_merge_type():
    with pytest.raises(m.LWWMapError):
        m.LWWMap().merge("nope")
def test_stdlib():
    assert m.stdlib_only()
