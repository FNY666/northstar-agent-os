"""Confidence gate tests."""

import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cg = _load("confidence_gate")


def test_high_low_risk():
    g = cg.ConfidenceGate()
    v = g.check(95, "low")
    assert v.action == "allow"
    assert v.tier == cg.ConfidenceTier.HIGH


def test_high_high_risk():
    g = cg.ConfidenceGate()
    v = g.check(95, "high")
    assert v.action == "observer"


def test_medium():
    g = cg.ConfidenceGate()
    v = g.check(80, "low")
    assert v.action == "observer"
    assert v.tier == cg.ConfidenceTier.MEDIUM


def test_low():
    g = cg.ConfidenceGate()
    v = g.check(60, "low")
    assert v.action == "escalate"


def test_unusable():
    g = cg.ConfidenceGate()
    v = g.check(30, "low")
    assert v.action == "deny"


def test_rejects_bad_confidence():
    g = cg.ConfidenceGate()
    with pytest.raises(cg.ConfidenceGateError):
        g.check(150, "low")
    with pytest.raises(cg.ConfidenceGateError):
        g.check(-1, "low")


def test_history():
    g = cg.ConfidenceGate()
    g.check(95, "low")
    assert len(g.history) == 1


def test_stdlib_only():
    assert cg.stdlib_only() is True


def test_version_pin():
    assert cg.CONFIDENCE_GATE_VERSION == "confidence-gate.v1"
