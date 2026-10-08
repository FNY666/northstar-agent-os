"""Tests for combo_16 (Floor-enforced execution)."""

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


combo = _load("combo_16")


def _ex(score=0.1):
    fs = combo.fs
    floors = [fs.Floor("f1", min_severity=10, required_detectors=frozenset({"tw"}))]
    return combo.FloorEnforcedExecution(floors, lambda tool, args: score)


def test_executes():
    ex = _ex()
    r = ex.execute(
        frozenset({"tw"}), frozenset(), 50,
        combo.dv.Consequence.REVERSIBLE_LOW, "read", {},
    )
    assert r["executed"] is True


def test_floor_fails():
    ex = _ex()
    try:
        ex.execute(frozenset(), frozenset(), 50, combo.dv.Consequence.REVERSIBLE_LOW, "r", {})
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_veto_fails():
    ex = _ex()
    try:
        ex.execute(
            frozenset({"tw"}), frozenset(), 50,
            combo.dv.Consequence.IRREVERSIBLE_BROAD, "rm", {},
        )
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_tier_denies():
    ex = _ex(score=0.95)
    try:
        ex.execute(
            frozenset({"tw"}), frozenset(), 50,
            combo.dv.Consequence.REVERSIBLE_LOW, "r", {},
        )
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_stdlib_only():
    assert combo.stdlib_only() is True
