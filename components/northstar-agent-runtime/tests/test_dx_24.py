"""Tests for dx_24. profiler."""
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

dx = _load("dx_24")

def _prof():
    p = dx.Profiler()
    p.sample("parse", 10.0)
    p.sample("parse", 20.0)
    p.sample("emit", 5.0)
    return p


def test_hotspots_ranked():
    hs = _prof().hotspots(limit=2)
    assert [(h.function, h.calls, h.total_ms) for h in hs] == [
        ("parse", 2, 30.0), ("emit", 1, 5.0)
    ]
    assert hs[0].mean_ms == 15.0


def test_negative_rejected():
    p = dx.Profiler()
    with pytest.raises(dx.ProfilerError):
        p.sample("x", -1.0)


def test_reset():
    p = _prof()
    p.reset()
    assert p.hotspots() == []


def test_bad_limit_raises():
    with pytest.raises(dx.ProfilerError):
        _prof().hotspots(limit=0)


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX24_PROFILER_VERSION == "dx-profiler.v1"
