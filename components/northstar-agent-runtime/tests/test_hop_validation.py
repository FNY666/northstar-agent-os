"""Hop validation tests."""

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


hv = _load("hop_validation")


def test_valid():
    s = hv.HopSchema("h1", frozenset({"a", "b"}), frozenset({"a"}))
    v = hv.validate_hop({"a": 1, "b": 2}, s)
    assert v == {"a": 1, "b": 2}


def test_missing_required():
    s = hv.HopSchema("h1", frozenset({"a"}), frozenset({"a", "b"}))
    with pytest.raises(hv.HopValidationError):
        hv.validate_hop({"a": 1}, s)


def test_unknown_isolated():
    s = hv.HopSchema("h1", frozenset({"a"}), frozenset({"a"}))
    with pytest.raises(hv.HopValidationError) as exc:
        hv.validate_hop({"a": 1, "evil": 2}, s)
    assert "isolate" in str(exc.value)


def test_growth_anomaly():
    assert hv.detect_growth_anomaly([100, 100, 100, 500]) is True
    assert hv.detect_growth_anomaly([100, 100, 100, 110]) is False


def test_no_anomaly_small():
    assert hv.detect_growth_anomaly([100, 110]) is False


def test_stdlib_only():
    assert hv.stdlib_only() is True


def test_version_pin():
    assert hv.HOP_VALIDATION_VERSION == "hop-validation.v1"
