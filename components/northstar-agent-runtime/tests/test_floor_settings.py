"""Floor settings tests."""

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


fs = _load("floor_settings")


def test_compliant():
    e = fs.FloorEnforcer([
        fs.Floor("r", min_severity=50,
                 required_detectors=frozenset({"a"}),
                 always_deny=frozenset({"x"}))
    ])
    ok, _ = e.check_policy(
        frozenset({"a", "b"}), frozenset({"x", "y"}), 60
    )
    assert ok is True


def test_missing_detector():
    e = fs.FloorEnforcer([
        fs.Floor("r", required_detectors=frozenset({"a", "b"}))
    ])
    ok, _ = e.check_policy(frozenset({"a"}), frozenset(), 0)
    assert ok is False


def test_weakened_severity():
    e = fs.FloorEnforcer([fs.Floor("r", min_severity=80)])
    ok, _ = e.check_policy(frozenset(), frozenset(), 50)
    assert ok is False


def test_allows_denied_tool():
    e = fs.FloorEnforcer([
        fs.Floor("r", always_deny=frozenset({"bad_tool"}))
    ])
    ok, _ = e.check_policy(frozenset(), frozenset(), 0)
    assert ok is False


def test_floor_hash():
    e = fs.FloorEnforcer([fs.Floor("r")])
    assert e.floor_hash.startswith("sha256:")


def test_requires_floors():
    import pytest
    with pytest.raises(fs.FloorError):
        fs.FloorEnforcer([])


def test_stdlib_only():
    assert fs.stdlib_only() is True


def test_version_pin():
    assert fs.FLOOR_VERSION == "floor-settings.v1"
