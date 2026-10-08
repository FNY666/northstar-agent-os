"""Tests for combo_10 (Tiered confidence execution)."""

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


combo = _load("combo_10")


def _ex(score=0.1):
    return combo.TieredConfidenceExecution(lambda tool, args: score)


def test_clean_executes():
    ex = _ex()
    r = ex.execute("read", {}, 95, "low", combo.dv.Consequence.REVERSIBLE_LOW)
    assert r["executed"] is True


def test_low_confidence_denied():
    ex = _ex()
    try:
        ex.execute("read", {}, 5, "high", combo.dv.Consequence.REVERSIBLE_LOW)
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_irreversible_vetoed():
    ex = _ex()
    try:
        ex.execute("x", {}, 95, "low", combo.dv.Consequence.IRREVERSIBLE_BROAD)
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_tier_deny():
    ex = _ex(score=0.95)
    try:
        ex.execute("x", {}, 95, "low", combo.dv.Consequence.REVERSIBLE_LOW)
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_stdlib_only():
    assert combo.stdlib_only() is True
