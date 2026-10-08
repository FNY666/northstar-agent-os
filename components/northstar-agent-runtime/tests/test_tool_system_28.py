"""Tests for tool_system_28."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_28")
import pytest

def test_chain_with_placeholders():
    c = m.Composer()
    c.add_step("a", "t1", {"q": "hello"})
    c.add_step("b", "t2", {"in": "${a.out}", "tags": ["x", "${a.out}"]})
    out = c.run({
        "t1": lambda args: {"out": f"got:{args['q']}"},
        "t2": lambda args: {"echo": args["in"], "tags": args["tags"]},
    })
    assert out["b"] == {"echo": "got:hello", "tags": ["x", "got:hello"]}

def test_missing_step_reference():
    c = m.Composer()
    c.add_step("a", "t", {"x": "${ghost.f}"})
    with pytest.raises(m.CompositionError):
        c.run({"t": lambda args: {}})

def test_forward_reference_rejected():
    c = m.Composer()
    c.add_step("a", "t", {"x": "${b.out}"})
    c.add_step("b", "t", {})
    with pytest.raises(m.CompositionError):
        c.run({"t": lambda args: {"out": "v"}})

def test_self_reference_rejected():
    c = m.Composer()
    c.add_step("a", "t", {"x": "${a.out}"})
    with pytest.raises(m.CompositionError):
        c.run({"t": lambda args: {}})

def test_failed_step():
    def _boom(args):
        raise RuntimeError("kaput")
    c = m.Composer()
    c.add_step("a", "t", {})
    with pytest.raises(m.StepFailed) as ei:
        c.run({"t": _boom})
    assert ei.value.step == "a"

def test_missing_executor():
    c = m.Composer()
    c.add_step("a", "nosuchtool", {})
    with pytest.raises(m.CompositionError):
        c.run({})

def test_stdlib():
    assert m.stdlib_only() is True
