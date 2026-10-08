"""Tests for monitor_29 (timeline analysis)."""
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


tl = _load("monitor_29")


def _timeline():
    t = tl.Timeline()
    t.add("ndr", "c2", 100.0)
    t.add("edr", "persistence", 200.0)
    t.add("edr", "malware_exec", 300.0)
    return t


def test_build_sorted():
    t = _timeline()
    assert [e.ts for e in t.build()] == [100.0, 200.0, 300.0]


def test_window_and_source():
    t = _timeline()
    assert len(t.window(150.0, 250.0)) == 1
    assert len(t.by_source("edr")) == 2
    assert len(t.by_source("ndr")) == 1


def test_gaps_and_offsets():
    t = _timeline()
    assert t.gaps(150.0) == []
    assert t.gaps(100.0) == [(100.0, 200.0), (200.0, 300.0)]
    offs = t.offsets("c2")
    assert [d for _, d in offs] == [0.0, 100.0, 200.0]


def test_fail_closed():
    t = tl.Timeline()
    with pytest.raises(tl.TimelineError):
        t.add("s", "k", -1.0)
    with pytest.raises(tl.TimelineError):
        t.window(5.0, 1.0)
    with pytest.raises(tl.TimelineError):
        t.gaps(0)
    with pytest.raises(tl.TimelineError):
        t.offsets("nope")


def test_stdlib_only():
    assert tl.stdlib_only() is True
