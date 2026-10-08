"""Tests for combo_18 (Alignment-observed delegation)."""

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


combo = _load("combo_18")


def _d(judge=None):
    ac = combo.ac
    judge = judge or (lambda inp: ac.AlignmentJudgment(True, 0.9, "ok"))
    d = combo.AlignmentObservedDelegation(judge)
    d.register_command("fetch", combo.cr.AutonomyLevel.AUTOMATIC)
    return d


def test_delegates():
    d = _d()
    trace = [combo.ac.TraceEntry("action", "x")]
    r = d.delegate("g", trace, "a", "fetch")
    assert r["delegated"] == "fetch"
    assert r["events"] == ["pre", "post"]


def test_misaligned_fails():
    ac = combo.ac
    d = _d(lambda inp: ac.AlignmentJudgment(False, 0.1, "off"))
    trace = [ac.TraceEntry("action", "x")]
    try:
        d.delegate("g", trace, "a", "fetch")
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_unknown_command_fails():
    d = _d()
    trace = [combo.ac.TraceEntry("action", "x")]
    try:
        d.delegate("g", trace, "a", "ghost")
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_hook_can_block():
    d = _d()
    d.on(combo.lh.HookPoint.PRE_TOOL, lambda ctx: False)
    trace = [combo.ac.TraceEntry("action", "x")]
    try:
        d.delegate("g", trace, "a", "fetch")
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_stdlib_only():
    assert combo.stdlib_only() is True
