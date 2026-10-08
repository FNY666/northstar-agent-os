"""Tests for monitor_23 (dark-web monitoring)."""
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


dw = _load("monitor_23")


def test_match_and_severity():
    m = dw.DarkWebMonitor()
    m.watch("acme.com", "domain", 80)
    m.watch("admin@acme.com", "email", 90)
    got = m.ingest("f1", "forum", "leak: acme.com admin@acme.com", ts=1.0)
    assert len(got) == 2
    by_term = {a.term: a for a in got}
    assert by_term["acme.com"].severity == 80
    assert by_term["admin@acme.com"].severity == 90


def test_dedupe_and_unwatch():
    m = dw.DarkWebMonitor()
    m.watch("falcon", "keyword", 60)
    assert len(m.ingest("f1", "s", "falcon files", ts=1.0)) == 1
    assert m.ingest("f1", "s", "falcon again", ts=2.0) == []
    assert len(m.ingest("f2", "s", "FALCON", ts=3.0)) == 1  # case-insensitive
    m.unwatch("falcon")
    assert m.ingest("f3", "s", "falcon", ts=4.0) == []


def test_fail_closed():
    m = dw.DarkWebMonitor()
    with pytest.raises(dw.DarkWebError):
        m.watch("x", "bogus", 50)
    with pytest.raises(dw.DarkWebError):
        m.watch("x", "domain", 101)
    with pytest.raises(dw.DarkWebError):
        m.unwatch("ghost")
    with pytest.raises(dw.DarkWebError):
        m.ingest("", "s", "t")


def test_stdlib_only():
    assert dw.stdlib_only() is True
