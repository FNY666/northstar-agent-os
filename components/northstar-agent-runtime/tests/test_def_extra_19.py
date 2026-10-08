"""Tests for def_extra_19 (downgrade attack detection)."""
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


m = _load("def_extra_19")


def test_normal_negotiation_ok():
    det = m.DowngradeDetector()
    down, _ = det.observe(m.Negotiation("srv", "TLS1.3", "TLS1.3", []))
    assert down is False


def test_rollback_detected():
    det = m.DowngradeDetector()
    det.observe(m.Negotiation("srv", "TLS1.3", "TLS1.3", []))
    down, detail = det.observe(m.Negotiation("srv", "TLS1.3", "TLS1.2", []))
    assert down is True
    assert "rollback" in detail


def test_flag_strip_detected():
    det = m.DowngradeDetector()
    down, detail = det.observe(m.Negotiation("srv", "TLS1.3", "TLS1.3", ["starttls"]))
    assert down is True
    assert "stripped" in detail


def test_unknown_version_rejected():
    det = m.DowngradeDetector()
    with pytest.raises(m.DowngradeError):
        det.observe(m.Negotiation("srv", "TLS9.9", "TLS9.9", []))


def test_version_pin():
    assert m.DEF_EXTRA_19_VERSION == "def-extra-19.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-19.v1"
