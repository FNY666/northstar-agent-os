"""Integration 08 tests."""

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
fs = _load("floor_settings")
i08 = _load("integration_08")

SCHEMA = hv.HopSchema(
    hop_id="h1",
    allowed_fields=frozenset({"task", "data"}),
    required_fields=frozenset({"task"}),
    max_size=1000,
)

ENFORCER = fs.FloorEnforcer([
    fs.Floor(
        "root",
        min_severity=50,
        required_detectors=frozenset({"injection"}),
        always_deny=frozenset({"rm_rf"}),
    )
])


def _handoff():
    return i08.FloorValidatedHandoff(ENFORCER)


def test_valid_hop_and_floor():
    v = _handoff().validate(
        {"task": "do", "data": "x"}, SCHEMA,
        frozenset({"injection"}), frozenset({"rm_rf"}), 70,
    )
    assert v == {"task": "do", "data": "x"}


def test_unknown_field_raises():
    with pytest.raises(i08.HopValidationError):
        _handoff().validate(
            {"task": "do", "evil": 1}, SCHEMA,
            frozenset({"injection"}), frozenset({"rm_rf"}), 70,
        )


def test_weak_policy_raises():
    with pytest.raises(i08.IntegrationError) as exc:
        _handoff().validate(
            {"task": "do"}, SCHEMA,
            frozenset(), frozenset({"rm_rf"}), 70,
        )
    assert "floor" in str(exc.value)


def test_weakened_severity_raises():
    with pytest.raises(i08.IntegrationError):
        _handoff().validate(
            {"task": "do"}, SCHEMA,
            frozenset({"injection"}), frozenset({"rm_rf"}), 30,
        )


def test_version_pin():
    assert i08.INTEGRATION_08_VERSION == "integration-08.v1"
    assert i08.stdlib_only() is True
