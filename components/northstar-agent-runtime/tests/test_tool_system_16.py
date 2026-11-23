"""Tests for tool_system_16."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_16")
import pytest

def _qm():
    now = {"t": 0.0}
    qm = m.QuotaManager(clock=lambda: now["t"])
    qm.set_quota("t", limit=2, window_seconds=60.0)
    return qm, now

def test_consume_and_exhausted():
    qm, _ = _qm()
    qm.consume("t"); qm.consume("t")
    with pytest.raises(m.QuotaExceeded):
        qm.consume("t")

def test_remaining():
    qm, _ = _qm()
    assert qm.remaining("t") == 2
    qm.consume("t")
    assert qm.remaining("t") == 1

def test_window_roll():
    qm, now = _qm()
    qm.consume("t"); qm.consume("t")
    now["t"] = 61.0
    assert qm.remaining("t") == 2
    qm.consume("t")  # works in the new window

def test_manual_reset():
    qm, _ = _qm()
    qm.consume("t"); qm.consume("t")
    qm.reset_window("t")
    assert qm.remaining("t") == 2

def test_unknown_tool():
    qm, _ = _qm()
    with pytest.raises(m.ToolSystem16Error):
        qm.consume("nope")

def test_bad_quota():
    qm, _ = _qm()
    with pytest.raises(m.ToolSystem16Error):
        qm.set_quota("x", limit=0, window_seconds=60)

def test_stdlib():
    assert m.stdlib_only() is True
