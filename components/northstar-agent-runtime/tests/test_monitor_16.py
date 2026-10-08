"""Tests for monitor_16 (NDR)."""
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


nd = _load("monitor_16")


def _ndr():
    return nd.Ndr(
        window_s=300.0, port_scan_ports=10, exfil_bytes=1000,
        beacon_min_conns=5, beacon_max_jitter=0.25, lateral_hosts=5,
    )


def test_port_scan():
    n = _ndr()
    for p in range(20, 32):
        n.ingest(nd.Flow("10.0.0.5", "8.8.8.8", p, "tcp", 60, float(p)))
    kinds = [a.kind for a in n.alerts()]
    assert "port_scan" in kinds
    # Dedupe: one more port does not re-fire.
    n.ingest(nd.Flow("10.0.0.5", "8.8.8.8", 99, "tcp", 60, 100.0))
    assert [a.kind for a in n.alerts()].count("port_scan") == 1


def test_exfil_and_benign():
    n = _ndr()
    assert n.ingest(nd.Flow("10.0.0.5", "10.9.9.9", 443, "tcp", 5000, 1.0)) == []
    got = n.ingest(nd.Flow("10.0.0.5", "1.2.3.4", 443, "tcp", 2000, 2.0))
    assert any(a.kind == "exfil" for a in got)


def test_beaconing_and_lateral():
    n = _ndr()
    for i in range(6):
        n.ingest(nd.Flow("10.0.0.6", "9.9.9.9", 443, "tcp", 100, 1000.0 + i * 60))
    assert any(a.kind == "beaconing" for a in n.alerts())
    for i in range(6):
        n.ingest(nd.Flow("10.0.0.7", f"192.168.1.{i + 1}", 445, "tcp", 100, 2000.0 + i))
    assert any(a.kind == "lateral_movement" for a in n.alerts())


def test_fail_closed():
    n = _ndr()
    with pytest.raises(nd.NdrError):
        nd.Flow("a", "b", 0, "tcp", 1, 1.0)
    with pytest.raises(nd.NdrError):
        nd.Flow("a", "b", 80, "gre", 1, 1.0)
    with pytest.raises(nd.NdrError):
        n.ingest("nope")
    with pytest.raises(nd.NdrError):
        nd.Ndr(window_s=-1)


def test_stdlib_only():
    assert nd.stdlib_only() is True
