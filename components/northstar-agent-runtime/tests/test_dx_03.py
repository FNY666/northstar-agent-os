"""Tests for dx_03 mock debugger."""
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

dx = _load("dx_03")


def test_breakpoint_hit():
    dbg = dx.MockDebugger([(1, "a"), (2, "b"), (3, "c")])
    dbg.set_breakpoint(2)
    f = dbg.continue_()
    assert f.line_no == 2 and not f.halted
    assert dbg.breakpoint_hits == [2]


def test_step_and_halt():
    dbg = dx.MockDebugger([(1, "a"), (2, "b")])
    assert dbg.step().line_no == 1
    assert dbg.step().line_no == 2
    assert dbg.step().halted is True


def test_bad_breakpoint_raises():
    dbg = dx.MockDebugger([(1, "a")])
    with pytest.raises(dx.DebuggerError):
        dbg.set_breakpoint(99)


def test_inspect_and_set_variable():
    dbg = dx.MockDebugger([(1, "a")], {"x": 1})
    assert dbg.inspect("x") == 1
    dbg.set_variable("x", 2)
    assert dbg.inspect("x") == 2
    with pytest.raises(dx.DebuggerError):
        dbg.inspect("missing")


def test_clear_breakpoint():
    dbg = dx.MockDebugger([(1, "a"), (2, "b")])
    dbg.set_breakpoint(1)
    dbg.clear_breakpoint(1)
    assert dbg.breakpoints == []
    f = dbg.continue_()
    assert f.halted is True


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX03_DEBUGGER_VERSION == "dx-debugger.v1"
