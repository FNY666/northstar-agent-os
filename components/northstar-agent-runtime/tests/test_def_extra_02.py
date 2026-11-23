"""Tests for def_extra_02 (device fingerprinting mock)."""
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


m = _load("def_extra_02")

ATTRS = {"os": "linux", "screen": "1920x1080", "tz": "UTC"}


def test_register_and_verify():
    reg = m.DeviceRegistry()
    record = reg.register("d1", ATTRS)
    assert record.fingerprint.startswith("fp:")
    ok, changed = reg.verify("d1", dict(ATTRS))
    assert ok is True
    assert changed == []


def test_fingerprint_stable():
    assert m.fingerprint(ATTRS) == m.fingerprint(dict(ATTRS))


def test_drift_beyond_tolerance():
    reg = m.DeviceRegistry(max_changed_keys=0)
    reg.register("d1", ATTRS)
    other = dict(ATTRS)
    other["os"] = "windows"
    ok, changed = reg.verify("d1", other)
    assert ok is False
    assert changed == ["os"]


def test_unknown_device_fail_closed():
    reg = m.DeviceRegistry()
    ok, _ = reg.verify("nope", ATTRS)
    assert ok is False


def test_version_pin():
    assert m.DEF_EXTRA_02_VERSION == "def-extra-02.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-02.v1"
