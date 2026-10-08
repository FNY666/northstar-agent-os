"""Tests for monitor_22 (tripwires)."""
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


tw = _load("monitor_22")

H1 = "a" * 64
H2 = "b" * 64


def test_verify_statuses():
    t = tw.TripwireSet()
    t.add("/etc/passwd", H1)
    t.add("/etc/shadow", H2)
    r = t.verify({"/etc/passwd": H1, "/etc/shadow": "c" * 64, "/tmp/x": H1})
    assert r["/etc/passwd"] == "ok"
    assert r["/etc/shadow"] == "changed"
    assert r["/tmp/x"] == "unexpected"
    assert t.verify({"/etc/passwd": H1})["/etc/shadow"] == "missing"


def test_summary_and_remove():
    t = tw.TripwireSet()
    t.add("/a", H1)
    t.add("/b", H2)
    assert t.summary({"/a": H1, "/b": H2}) == {
        "ok": 2, "changed": 0, "missing": 0, "unexpected": 0,
    }
    t.remove("/b")
    assert t.verify({"/a": H1}) == {"/a": "ok"}


def test_fail_closed():
    t = tw.TripwireSet()
    with pytest.raises(tw.TripwireError):
        t.add("/x", "not-hex")
    with pytest.raises(tw.TripwireError):
        t.add("/x", "A" * 64)
    with pytest.raises(tw.TripwireError):
        t.add("", H1)
    with pytest.raises(tw.TripwireError):
        t.remove("/ghost")
    with pytest.raises(tw.TripwireError):
        t.verify("nope")


def test_stdlib_only():
    assert tw.stdlib_only() is True
