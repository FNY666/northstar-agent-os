"""Tests for def_extra_01 (behavioral biometrics mock)."""
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


m = _load("def_extra_01")


def test_enroll_and_verify_ok():
    store = m.BehaviorStore(min_samples=3)
    store.enroll("alice", [100.0, 102.0, 98.0, 101.0])
    ok, score = store.verify("alice", [99.0, 103.0])
    assert ok is True
    assert 0.0 <= score <= 1.0


def test_anomaly_rejected():
    store = m.BehaviorStore(min_samples=3)
    store.enroll("alice", [100.0, 102.0, 98.0, 101.0])
    ok, _ = store.verify("alice", [2000.0, 3000.0])
    assert ok is False


def test_unknown_principal_fail_closed():
    store = m.BehaviorStore(min_samples=3)
    ok, score = store.verify("ghost", [100.0])
    assert ok is False
    assert score == 1.0


def test_too_few_samples_rejected():
    store = m.BehaviorStore(min_samples=5)
    with pytest.raises(m.BehavioralError):
        store.enroll("alice", [100.0, 101.0])


def test_version_pin():
    assert m.DEF_EXTRA_01_VERSION == "def-extra-01.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-01.v1"
