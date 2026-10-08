"""Tests for combo_07 (Observed execution)."""

import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


combo = _load("combo_07")


def _ex():
    return combo.ObservedExecution(lambda tool, args: "ok")


def test_executes_with_reasoning():
    ex = _ex()
    assert ex.execute("because", "ls", {}) == "ok"


def test_missing_reasoning_fails():
    ex = _ex()
    try:
        ex.execute(None, "ls", {})
    except combo.it.InterleavedError:
        return
    raise AssertionError("expected InterleavedError")


def test_pre_hook_deny_blocks():
    ex = _ex()
    ex.on(combo.lh.HookPoint.PRE_TOOL, lambda ctx: False)
    try:
        ex.execute("r", "ls", {})
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_snapshot_records():
    ex = _ex()
    ex.execute("r", "ls", {"a": 1})
    assert len(ex.snapshot.tool_calls) == 1
    assert ex.snapshot.tool_calls[0].tool_name == "ls"


def test_stdlib_only():
    assert combo.stdlib_only() is True
