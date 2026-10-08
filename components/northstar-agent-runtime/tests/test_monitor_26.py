"""Tests for monitor_26 (takedown automation)."""
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


td = _load("monitor_26")


def test_full_workflow():
    b = td.TakedownBoard()
    cid = b.report("evil.tk/", "phishing_url", ts=100.0)
    b.transition(cid, "submitted", ts=110.0)
    b.transition(cid, "in_review", ts=120.0)
    b.transition(cid, "taken_down", ts=130.0, evidence=b"bytes")
    case = b.get(cid)
    assert case.state == "taken_down"
    assert case.evidence_hash.startswith("sha256:")
    assert [(t.frm, t.to) for t in case.history] == [
        ("reported", "submitted"), ("submitted", "in_review"),
        ("in_review", "taken_down"),
    ]


def test_reject_path_and_sla():
    b = td.TakedownBoard()
    cid = b.report("x.com", "fake_domain", ts=0.0, sla_s=100.0)
    assert b.sla_breached(cid, 50.0) is False
    assert b.sla_breached(cid, 101.0) is True
    b.transition(cid, "submitted", ts=10.0)
    b.transition(cid, "rejected", ts=20.0, note="false positive")
    assert b.get(cid).state == "rejected"
    assert b.sla_breached(cid, 9999.0) is False


def test_fail_closed():
    b = td.TakedownBoard()
    cid = b.report("x.com", "malware_host", ts=0.0)
    with pytest.raises(td.TakedownError):
        b.transition(cid, "in_review", ts=1.0)  # must go via submitted
    with pytest.raises(td.TakedownError):
        b.transition("TD-9999", "submitted", ts=1.0)
    with pytest.raises(td.TakedownError):
        b.report("", "phishing_url", ts=1.0)
    b.transition(cid, "submitted", ts=1.0)
    b.transition(cid, "in_review", ts=2.0)
    with pytest.raises(td.TakedownError):
        b.transition(cid, "taken_down", ts=3.0)  # evidence required


def test_stdlib_only():
    assert td.stdlib_only() is True
