"""Tests for monitor_17 (EDR)."""
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


ed = _load("monitor_17")


def _edr():
    e = ed.Edr(bad_ips={"6.6.6.6"}, ransom_threshold=5, window_s=300.0)
    e.register_endpoint("ep1", "WS-01")
    return e


def _ev(kind, ts, fields):
    return ed.EdrEvent("ep1", kind, ts, fields)


def test_suspicious_parent_and_unsigned():
    e = _edr()
    got = e.ingest(_ev("process", 1.0, {
        "image": "powershell.exe", "parent": "winword.exe",
        "signed": True, "pid": 1,
    }))
    assert any(a.kind == "suspicious_parent" and a.severity == 90 for a in got)
    got = e.ingest(_ev("process", 2.0, {
        "image": "evil.exe", "parent": "explorer.exe",
        "signed": False, "pid": 2,
    }))
    assert any(a.kind == "unsigned_exec" for a in got)


def test_ransomware_c2_persistence():
    e = _edr()
    for i in range(5):
        e.ingest(_ev("file", 10.0 + i, {"path": f"C:\\x\\f{i}.enc", "op": "write"}))
    assert any(a.kind == "ransomware" for a in e.alerts())
    got = e.ingest(_ev("net", 20.0, {"dst_ip": "6.6.6.6", "dst_port": 443}))
    assert any(a.kind == "c2" for a in got)
    got = e.ingest(_ev("registry", 21.0, {
        "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "op": "set",
    }))
    assert any(a.kind == "persistence" for a in got)


def test_actions_and_isolation():
    e = _edr()
    assert e.is_isolated("ep1") is False
    e.isolate_endpoint("ep1")
    assert e.is_isolated("ep1") is True
    e.kill_process("ep1", 99)
    assert [a.action for a in e.actions()] == ["isolate", "kill_process"]


def test_fail_closed():
    e = _edr()
    with pytest.raises(ed.EdrError):
        e.ingest(ed.EdrEvent("ghost", "process", 1.0, {"image": "a.exe"}))
    with pytest.raises(ed.EdrError):
        e.ingest(ed.EdrEvent("ep1", "bogus", 1.0, {}))
    with pytest.raises(ed.EdrError):
        e.isolate_endpoint("ghost")
    with pytest.raises(ed.EdrError):
        e.kill_process("ep1", -1)


def test_stdlib_only():
    assert ed.stdlib_only() is True
