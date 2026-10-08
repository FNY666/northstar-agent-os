"""Tests for tool_system_29."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_29")
import pytest

def test_topo_order():
    seen = []
    o = m.Orchestrator()
    o.add_task("c", lambda: seen.append("c") or 3, deps=["b"])
    o.add_task("a", lambda: seen.append("a") or 1)
    o.add_task("b", lambda: seen.append("b") or 2, deps=["a"])
    res = o.run()
    assert seen == ["a", "b", "c"]
    assert res == {"a": 1, "b": 2, "c": 3}

def test_parallel_groups():
    o = m.Orchestrator()
    o.add_task("a", lambda: 1)
    o.add_task("b", lambda: 2)
    o.add_task("c", lambda: 3, deps=["a", "b"])
    assert o.parallel_groups() == [["a", "b"], ["c"]]

def test_cycle_raises():
    o = m.Orchestrator()
    o.add_task("a", lambda: 1, deps=["b"])
    o.add_task("b", lambda: 2, deps=["a"])
    with pytest.raises(m.CycleError):
        o.run()

def test_failed_task_halts_dependents():
    ran = []
    o = m.Orchestrator()
    o.add_task("ok", lambda: ran.append("ok") or 1)
    def _boom():
        ran.append("boom")
        raise RuntimeError("kaput")
    o.add_task("fail", _boom)
    o.add_task("child", lambda: ran.append("child") or 3, deps=["fail"])
    o.add_task("grandchild", lambda: ran.append("grandchild") or 4,
               deps=["child"])
    with pytest.raises(m.TaskFailed) as ei:
        o.run()
    assert ei.value.task == "fail"
    assert set(ei.value.halted) == {"child", "grandchild"}
    assert "child" not in ran and "grandchild" not in ran
    assert "ok" in ran  # independent task still ran

def test_unknown_dep():
    o = m.Orchestrator()
    o.add_task("a", lambda: 1, deps=["ghost"])
    with pytest.raises(m.ToolSystem29Error):
        o.run()

def test_stdlib():
    assert m.stdlib_only() is True
