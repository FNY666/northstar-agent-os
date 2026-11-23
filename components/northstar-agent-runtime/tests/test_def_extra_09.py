"""Tests for def_extra_09 (audit trail verification)."""
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


m = _load("def_extra_09")


def _trail():
    return [
        m.AuditEntry(1, "genesis", "h1", "start"),
        m.AuditEntry(2, "h1", "h2", "allow"),
        m.AuditEntry(3, "h2", "h3", "deny"),
    ]


def test_valid_trail():
    ok, detail = m.verify_trail(_trail())
    assert ok is True, detail


def test_seq_gap_detected():
    trail = _trail()[:2] + [m.AuditEntry(4, "h2", "h4", "x")]
    ok, detail = m.verify_trail(trail)
    assert ok is False
    assert "gap" in detail


def test_broken_link_detected():
    trail = _trail()[:2] + [m.AuditEntry(3, "WRONG", "h3", "x")]
    ok, detail = m.verify_trail(trail)
    assert ok is False
    assert "link" in detail


def test_empty_trail_ok():
    ok, _ = m.verify_trail([])
    assert ok is True


def test_version_pin():
    assert m.DEF_EXTRA_09_VERSION == "def-extra-09.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-09.v1"
