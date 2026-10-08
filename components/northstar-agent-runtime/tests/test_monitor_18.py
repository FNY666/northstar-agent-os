"""Tests for monitor_18 (XDR)."""
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


xd = _load("monitor_18")


def _a(source, kind, entity, sev, ts):
    return xd.XdrAlert(source, kind, entity, sev, ts)


def test_correlate_and_score():
    x = xd.Xdr(window_s=3600.0)
    i1 = x.ingest(_a("ndr", "port_scan", "h1", 70, 100.0))
    i2 = x.ingest(_a("edr", "c2", "h1", 85, 200.0))
    assert i1 == i2
    inc = x.get(i1)
    assert inc.sources == {"ndr", "edr"}
    assert inc.severity == 95
    i3 = x.ingest(_a("identity", "impossible_travel", "h1", 60, 300.0))
    assert i3 == i1
    assert x.get(i1).severity == 100  # capped: 85 + 20


def test_dedupe_and_split():
    x = xd.Xdr(window_s=3600.0)
    i1 = x.ingest(_a("ndr", "port_scan", "h1", 70, 100.0))
    assert x.ingest(_a("ndr", "port_scan", "h1", 70, 200.0)) == i1
    assert len(x.get(i1).alerts) == 1
    assert x.ingest(_a("ndr", "port_scan", "h2", 70, 200.0)) != i1
    assert x.ingest(_a("ndr", "port_scan", "h1", 70, 100000.0)) != i1


def test_close():
    x = xd.Xdr()
    i1 = x.ingest(_a("ndr", "port_scan", "h1", 70, 100.0))
    x.close(i1)
    assert x.get(i1).status == "closed"
    assert x.open_incidents() == []
    # New alert after close opens a fresh incident.
    i2 = x.ingest(_a("ndr", "port_scan", "h1", 70, 200.0))
    assert i2 != i1


def test_fail_closed():
    x = xd.Xdr()
    with pytest.raises(xd.XdrError):
        xd.XdrAlert("s", "k", "e", 0, 1.0)
    with pytest.raises(xd.XdrError):
        x.ingest("nope")
    with pytest.raises(xd.XdrError):
        x.get("INC-4242")


def test_stdlib_only():
    assert xd.stdlib_only() is True
