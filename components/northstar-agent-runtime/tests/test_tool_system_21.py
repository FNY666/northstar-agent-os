"""Tests for tool_system_21."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_21")
import pytest

def _dep(**kw):
    kw.setdefault("stages", (10, 50, 100))
    kw.setdefault("error_threshold", 0.1)
    return m.CanaryDeployer("search", "v2", **kw)

def test_advance_through_stages():
    d = _dep()
    assert d.current_stage() == 10
    assert d.advance() == 50
    assert d.advance() == 100
    assert d.complete()
    with pytest.raises(m.ToolSystem21Error):
        d.advance()

def test_record_auto_pause():
    d = _dep()
    d.record(100, 2)  # 2% -- fine
    assert d.status()["paused"] is False
    d.record(100, 20)  # cumulative 22/200 = 11% > 10% -> pause
    assert d.status()["paused"] is True

def test_paused_blocks_advance_until_resume():
    d = _dep()
    d.record(100, 100)
    assert d.status()["paused"] is True
    with pytest.raises(m.DeployPaused):
        d.advance()
    d.resume()
    assert d.status()["paused"] is False
    assert d.advance() == 50

def test_status_reports_stage_and_paused():
    d = _dep()
    st = d.status()
    assert st["stage_pct"] == 10
    assert st["paused"] is False
    assert st["stage_error_rate"] == 0.0

def test_bad_config_and_metrics():
    with pytest.raises(m.ToolSystem21Error):
        m.CanaryDeployer("", "v2")
    with pytest.raises(m.ToolSystem21Error):
        m.CanaryDeployer("t", "v2", stages=())
    d = _dep()
    with pytest.raises(m.ToolSystem21Error):
        d.record(10, 20)

def test_stdlib():
    assert m.stdlib_only() is True
