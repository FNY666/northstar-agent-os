"""Tests for combo_03 (Layered injection defense)."""

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


combo = _load("combo_03")


def test_mark_contains_nonce():
    d = combo.LayeredInjectionDefense()
    m = d.mark("data")
    assert m["nonce"] in m["marked"]


def test_calibrate_block_all():
    d = combo.LayeredInjectionDefense()
    cal = d.calibrate(lambda *a: True)
    assert cal["blocked"] == cal["total"]


def test_calibrate_allow_all():
    d = combo.LayeredInjectionDefense()
    cal = d.calibrate(lambda *a: False)
    assert cal["blocked"] == 0


def test_high_confidence_allowed():
    d = combo.LayeredInjectionDefense()
    assert d.decide(95, "low")["allowed"] is True


def test_low_confidence_denied():
    d = combo.LayeredInjectionDefense()
    assert d.decide(10, "high")["allowed"] is False


def test_stdlib_only():
    assert combo.stdlib_only() is True
