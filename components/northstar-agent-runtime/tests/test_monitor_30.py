"""Tests for monitor_30 (root cause analysis)."""
import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


rc = _load("monitor_30")


def _alerts():
    return [
        rc.IncidentAlert("c2", "h1", 300.0),
        rc.IncidentAlert("phishing_email", "h1", 100.0),
        rc.IncidentAlert("malware_exec", "h1", 200.0),
    ]


def test_chain_and_root():
    r = rc.analyze(_alerts())
    assert r.root_cause == "initial_access"
    assert r.chain == ("initial_access", "execution", "command_and_control")


def test_containments():
    r = rc.analyze(_alerts())
    assert "block sender/domain" in r.containments
    assert "isolate endpoint" in r.containments
    assert r.coverage == 1.0


def test_known_kinds():
    assert "ransomware" in rc.known_kinds()
    assert "c2" in rc.known_kinds()


def test_fail_closed():
    with pytest.raises(rc.RcaError):
        rc.analyze([])
    with pytest.raises(rc.RcaError):
        rc.analyze([rc.IncidentAlert("nope", "h1", 1.0)])
    with pytest.raises(rc.RcaError):
        rc.analyze(["nope"])


def test_stdlib_only():
    assert rc.stdlib_only() is True
