"""Tests for tool_system_22."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_22")
import pytest

def _bg():
    now = {"t": 1000.0}
    return m.BlueGreenDeploy("search", "v1", active="blue", clock=lambda: now["t"]), now

def test_deploy_and_switch():
    bg, now = _bg()
    assert bg.route() == "v1"
    bg.deploy_to_inactive("v2")
    now["t"] = 1001.0
    assert bg.switch() == "v2"
    assert bg.route() == "v2"
    assert bg.active_slot() == "green"

def test_switch_records_history():
    bg, now = _bg()
    bg.deploy_to_inactive("v2")
    now["t"] = 1005.0
    bg.switch()
    hist = bg.history()
    assert len(hist) == 1
    assert hist[0]["from_slot"] == "blue"
    assert hist[0]["to_slot"] == "green"
    assert hist[0]["version"] == "v2"
    assert hist[0]["ts"] == 1005.0

def test_switch_empty_inactive_fails():
    bg, _ = _bg()
    with pytest.raises(m.ToolSystem22Error):
        bg.switch()

def test_switch_back():
    bg, _ = _bg()
    bg.deploy_to_inactive("v2")
    bg.switch()
    bg.deploy_to_inactive("v3")
    assert bg.switch() == "v3"
    assert bg.route() == "v3"
    assert bg.active_slot() == "blue"
    assert len(bg.history()) == 2

def test_bad_init():
    with pytest.raises(m.ToolSystem22Error):
        m.BlueGreenDeploy("t", "v1", active="red")
    with pytest.raises(m.ToolSystem22Error):
        m.BlueGreenDeploy("t", "")

def test_stdlib():
    assert m.stdlib_only() is True
