"""Tests for combo_14 (Spec-driven toolchain)."""

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


combo = _load("combo_14")


def _tc():
    ds = combo.ds
    spec = {"c1": ds.SpecClause("c1", "t")}
    tc = combo.SpecDrivenToolchain(spec)
    definition = {"name": "read", "v": "1"}
    tc.pin_tool("read", definition)
    tc.register_command("read", combo.cr.AutonomyLevel.AUTOMATIC)
    return tc, definition


def test_full_invoke():
    tc, definition = _tc()
    r = tc.invoke("allow", ["c1"], "r", "read", definition, "read")
    assert r["invoked"] is True


def test_uncited_fails():
    tc, definition = _tc()
    try:
        tc.invoke("allow", ["ghost"], "r", "read", definition, "read")
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_unpinned_fails():
    tc, _ = _tc()
    try:
        tc.invoke("allow", ["c1"], "r", "read", {"name": "read", "v": "9"}, "read")
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_unknown_command_fails():
    tc, definition = _tc()
    try:
        tc.invoke("allow", ["c1"], "r", "read", definition, "ghost")
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_stdlib_only():
    assert combo.stdlib_only() is True
