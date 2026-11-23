"""Tests for def_extra_05 (risk scoring engine)."""
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


m = _load("def_extra_05")


def test_all_max_critical():
    engine = m.RiskEngine({"a": 1.0, "b": 1.0})
    score, band = engine.assess({"a": 1.0, "b": 1.0})
    assert score == 100.0
    assert band == "critical"


def test_all_zero_low():
    engine = m.RiskEngine({"a": 1.0})
    score, band = engine.assess({"a": 0.0})
    assert score == 0.0
    assert band == "low"


def test_weighted_mid():
    engine = m.RiskEngine({"a": 3.0, "b": 1.0})
    score, band = engine.assess({"a": 0.5, "b": 0.0})
    assert band == "medium"
    assert 25.0 <= score < 50.0


def test_unknown_signals_ignored():
    engine = m.RiskEngine({"a": 1.0})
    assert engine.score({"zzz": 1.0}) == 0.0


def test_out_of_range_rejected():
    engine = m.RiskEngine({"a": 1.0})
    with pytest.raises(m.RiskScoringError):
        engine.score({"a": 1.5})


def test_version_pin():
    assert m.DEF_EXTRA_05_VERSION == "def-extra-05.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-05.v1"
