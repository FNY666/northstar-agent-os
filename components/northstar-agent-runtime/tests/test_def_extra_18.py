"""Tests for def_extra_18 (pinning violation detection)."""
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


m = _load("def_extra_18")


def _enforcer():
    enf = m.PinningEnforcer()
    enf.pin(m.PinSet("example.com", {"spki-AAA"}, {"spki-BBB"}))
    return enf


def test_pin_match_ok():
    ok, _ = _enforcer().check("example.com", "spki-AAA")
    assert ok is True


def test_backup_pin_ok():
    ok, _ = _enforcer().check("example.com", "spki-BBB")
    assert ok is True


def test_violation_hard_fail():
    ok, detail = _enforcer().check("example.com", "spki-EVIL")
    assert ok is False
    assert "VIOLATION" in detail


def test_unknown_host_report_policy():
    ok, detail = _enforcer().check("other.com", "spki-X")
    assert ok is True
    assert "reported" in detail


def test_unknown_host_strict_policy():
    enf = m.PinningEnforcer(unknown_host_policy="strict")
    ok, _ = enf.check("other.com", "spki-X")
    assert ok is False


def test_version_pin():
    assert m.DEF_EXTRA_18_VERSION == "def-extra-18.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-18.v1"
