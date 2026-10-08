"""Tests for combo_05 (Aligned termination)."""

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


combo = _load("combo_05")


def _term(judge=None):
    ac = combo.ac
    judge = judge or (lambda inp: ac.AlignmentJudgment(True, 0.9, "ok"))
    spec = {"c1": combo.ds.SpecClause("c1", "be safe")}
    return combo.AlignedTermination(judge, spec, "goal")


def test_full_pass_terminates():
    t = _term()
    trace = [combo.ac.TraceEntry("action", "x")]
    r = t.decide(trace, "a", "allow", ["c1"], "r", {}, [])
    assert r["done"] is True
    assert r["judgment"].aligned is True


def test_misaligned_raises():
    ac = combo.ac
    t = _term(lambda inp: ac.AlignmentJudgment(False, 0.1, "off"))
    trace = [ac.TraceEntry("action", "x")]
    try:
        t.decide(trace, "a", "allow", ["c1"], "r", {}, [])
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_uncited_raises():
    t = _term()
    trace = [combo.ac.TraceEntry("action", "x")]
    try:
        t.decide(trace, "a", "allow", ["ghost"], "r", {}, [])
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_not_done_continues():
    t = _term()
    trace = [combo.ac.TraceEntry("action", "x")]
    r = t.decide(trace, "a", "allow", ["c1"], "r", {"n": 1}, ["t1"])
    assert r["done"] is False


def test_stdlib_only():
    assert combo.stdlib_only() is True
