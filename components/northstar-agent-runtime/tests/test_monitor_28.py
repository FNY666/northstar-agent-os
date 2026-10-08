"""Tests for monitor_28 (chain of custody)."""
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


co = _load("monitor_28")

H = "sha256:" + "a" * 64


def test_append_and_verify():
    log = co.CustodyLog("CASE-1")
    log.append("a1", "collected", H, ts=1.0)
    log.append("a1", "transferred", H, ts=2.0)
    ok, reason = log.verify()
    assert ok, reason
    assert len(log) == 2


def test_tamper_detected():
    log = co.CustodyLog("CASE-2")
    log.append("a1", "collected", H, ts=1.0)
    log.append("a1", "stored", H, ts=2.0)
    # Tamper: mutate the second entry's action via object replacement.
    entries = log._entries
    bad = co.CustodyEntry(
        seq=entries[1].seq, ts=entries[1].ts, actor=entries[1].actor,
        action="destroyed", item_hash=entries[1].item_hash,
        prev_hash=entries[1].prev_hash, entry_hash=entries[1].entry_hash,
    )
    entries[1] = bad
    ok, reason = log.verify()
    assert ok is False
    assert "tamper" in reason


def test_gap_detected():
    log = co.CustodyLog("CASE-3")
    log.append("a1", "collected", H, ts=1.0)
    log.append("a1", "stored", H, ts=2.0)
    del log._entries[0]
    ok, reason = log.verify()
    assert ok is False
    assert "gap" in reason or "seq" in reason


def test_export_and_fail_closed():
    log = co.CustodyLog("CASE-4")
    log.append("a1", "collected", H, ts=1.0)
    exp = log.export()
    assert exp[0]["entry_hash"].startswith("sha256:")
    with pytest.raises(co.CustodyError):
        co.CustodyLog("")
    with pytest.raises(co.CustodyError):
        log.append("a", "collected", "badhash", ts=1.0)
    with pytest.raises(co.CustodyError):
        log.append("", "collected", H, ts=1.0)


def test_stdlib_only():
    assert co.stdlib_only() is True
