"""Tests for tool_system_23."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_23")
import pytest

def _rm():
    now = {"t": 2000.0}
    rm = m.RollbackManager(clock=lambda: now["t"])
    rm.record_deploy("search", "v1")
    rm.record_deploy("search", "v2")
    rm.record_deploy("search", "v3")
    return rm, now

def test_current_returns_latest():
    rm, _ = _rm()
    assert rm.current("search") == "v3"

def test_rollback_to_known_version():
    rm, now = _rm()
    now["t"] = 2003.0
    assert rm.rollback_to("search", "v2") == "v2"
    assert rm.current("search") == "v2"
    assert [v for v, _ in rm.history("search")] == ["v1", "v2"]
    audit = rm.audit_log()
    assert len(audit) == 1
    assert audit[0]["from"] == "v3"
    assert audit[0]["to"] == "v2"
    assert audit[0]["ts"] == 2003.0

def test_rollback_unknown_version_fails():
    rm, _ = _rm()
    with pytest.raises(m.ToolSystem23Error):
        rm.rollback_to("search", "v9")
    with pytest.raises(m.ToolSystem23Error):
        rm.rollback_to("nope", "v1")

def test_pin_prevents_rollback_past_it():
    rm, _ = _rm()
    rm.pin("search", "v2")
    with pytest.raises(m.ToolSystem23Error):
        rm.rollback_to("search", "v1")
    assert rm.rollback_to("search", "v2") == "v2"

def test_pin_requires_known_version():
    rm, _ = _rm()
    with pytest.raises(m.ToolSystem23Error):
        rm.pin("search", "v9")

def test_stdlib():
    assert m.stdlib_only() is True
