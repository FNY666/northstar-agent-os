"""Tests for dx_17. diagnostics."""
import importlib.util, sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent

def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m

dx = _load("dx_17")

def _store():
    s = dx.DiagnosticStore()
    s.publish(dx.Diagnostic("a.py", 5, "warning", "unused var", "W1"))
    s.publish(dx.Diagnostic("a.py", 5, "error", "syntax", "E1"))
    s.publish(dx.Diagnostic("a.py", 2, "info", "note", "I1"))
    return s


def test_sorted_get():
    diags = _store().get("a.py")
    assert [(d.line, d.severity) for d in diags] == [
        (2, "info"), (5, "error"), (5, "warning")
    ]


def test_error_count():
    assert _store().error_count("a.py") == 1


def test_clear_returns_count():
    assert _store().clear("a.py") == 3


def test_unknown_severity_raises():
    s = dx.DiagnosticStore()
    with pytest.raises(dx.DiagnosticsError):
        s.publish(dx.Diagnostic("a.py", 1, "fatal", "x"))


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX17_DIAGNOSTICS_VERSION == "dx-diagnostics.v1"
