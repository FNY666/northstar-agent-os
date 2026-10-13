"""Tests for tool_system_24."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_24")
import pytest

def _hc():
    hc = m.HealthChecker()
    hc.register("search", "ping", lambda: True)
    hc.register("search", "quota", lambda: True)
    hc.register("files", "ping", lambda: True)
    return hc

def test_all_healthy():
    hc = _hc()
    assert hc.run() == {"search": True, "files": True}
    assert hc.summary() == {"tools": 2, "healthy": 2, "unhealthy": 0}

def test_failing_check_marks_unhealthy():
    hc = _hc()
    hc.register("files", "disk", lambda: False)
    assert hc.run()["files"] is False
    assert hc.run()["search"] is True
    assert hc.details("files") == {"ping": True, "disk": False}
    assert hc.summary()["unhealthy"] == 1

def test_raising_check_marks_unhealthy():
    hc = _hc()
    def boom():
        raise TimeoutError("simulated timeout")
    hc.register("search", "slow", boom)
    assert hc.run()["search"] is False
    assert hc.details("search")["slow"] is False

def test_checks_listing():
    hc = _hc()
    assert hc.checks("search") == ["ping", "quota"]
    assert hc.checks("nope") == []

def test_bad_registration():
    hc = m.HealthChecker()
    with pytest.raises(m.ToolSystem24Error):
        hc.register("", "ping", lambda: True)
    with pytest.raises(m.ToolSystem24Error):
        hc.register("t", "", lambda: True)
    with pytest.raises(m.ToolSystem24Error):
        hc.register("t", "ping", "not-callable")

def test_stdlib():
    assert m.stdlib_only() is True
