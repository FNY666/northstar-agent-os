"""Tests for tool_system_20."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_20")
import pytest

def test_boolean_flags():
    store = m.FeatureFlagStore()
    store.set("on", True)
    store.set("off", False)
    assert store.evaluate("on") is True
    assert store.evaluate("off") is False

def test_full_rollout():
    store = m.FeatureFlagStore()
    store.set("f", True, rollout_pct=100.0)
    assert all(store.evaluate("f", key=f"k{i}") for i in range(50))

def test_zero_rollout():
    store = m.FeatureFlagStore()
    store.set("f", True, rollout_pct=0.0)
    assert all(not store.evaluate("f", key=f"k{i}") for i in range(50))

def test_partial_rollout_deterministic():
    store = m.FeatureFlagStore()
    store.set("f", True, rollout_pct=50.0)
    first = [store.evaluate("f", key=f"k{i}") for i in range(200)]
    second = [store.evaluate("f", key=f"k{i}") for i in range(200)]
    assert first == second  # stable per key
    assert any(first) and not all(first)  # mixed over 200 keys

def test_unknown_flag():
    store = m.FeatureFlagStore()
    with pytest.raises(m.ToolSystem20Error):
        store.evaluate("nope")

def test_override_list_remove():
    store = m.FeatureFlagStore()
    store.set("b", True)
    store.set("a", False)
    store.set("b", False, rollout_pct=10.0)  # override
    names = [f.name for f in store.list_flags()]
    assert names == ["a", "b"]
    assert store.evaluate("b") is False
    store.remove("a")
    assert [f.name for f in store.list_flags()] == ["b"]
    store.remove("missing")  # no-op, no error

def test_bad_rollout():
    store = m.FeatureFlagStore()
    with pytest.raises(m.ToolSystem20Error):
        store.set("x", True, rollout_pct=120.0)

def test_stdlib():
    assert m.stdlib_only() is True
