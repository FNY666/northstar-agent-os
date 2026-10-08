"""Tests for tool_system_12."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_12")
import pytest

def _step(name, log, fail=False):
    def act():
        log.append(f"{name}:do")
        if fail: raise ValueError("x")
        return name
    def comp(): log.append(f"{name}:undo")
    return m.SagaStep(name, act, comp)

def test_all_succeed():
    r = m.run_saga([_step("a", []), _step("b", [])])
    assert r.completed and r.results == ["a", "b"]

def test_reverse_compensation():
    log = []
    r = m.run_saga([_step("a", log), _step("b", log), _step("c", log, fail=True)])
    assert not r.completed and r.compensated == ["b", "a"]
    assert log[-2:] == ["b:undo", "a:undo"]

def test_compensation_error_recorded():
    def badc(): raise RuntimeError("u")
    log = []
    s1 = m.SagaStep("x", lambda: log.append("x:do"), badc)
    r = m.run_saga([s1, _step("y", log, fail=True)])
    assert len(r.compensation_errors) == 1

def test_no_steps():
    with pytest.raises(m.ToolSystem12Error):
        m.run_saga([])

def test_stdlib():
    assert m.stdlib_only() is True
