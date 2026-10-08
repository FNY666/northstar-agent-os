"""Tests for def_extra_03 (geofencing)."""
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


m = _load("def_extra_03")


def _fence():
    return m.Geofence([m.Zone("hq", 22.54, 114.06, 50.0)])


def test_inside_zone():
    ok, zone = _fence().check(22.55, 114.07)
    assert ok is True
    assert zone == "hq"


def test_outside_zone():
    ok, zone = _fence().check(40.71, -74.0)
    assert ok is False
    assert zone is None


def test_no_zones_fail_closed():
    ok, _ = m.Geofence([]).check(22.55, 114.07)
    assert ok is False


def test_impossible_travel():
    fence = _fence()
    ok, _ = fence.check_travel("alice", 22.54, 114.06, now=1000.0)
    assert ok is True
    ok, reason = fence.check_travel("alice", 40.71, -74.0, now=1060.0)
    assert ok is False
    assert "impossible travel" in reason


def test_version_pin():
    assert m.DEF_EXTRA_03_VERSION == "def-extra-03.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-03.v1"
