"""Tests for monitor_05 (log aggregation)."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


lg = _load("monitor_05")


def test_log_and_query():
    agg = lg.Aggregator()
    agg.log("info", "gate", "allow")
    agg.log("error", "gate", "deny x")
    assert len(agg.query(level="error")) == 1
    assert len(agg.query(service="gate")) == 2
    assert len(agg.query(contains="deny")) == 1


def test_error_burst():
    agg = lg.Aggregator()
    agg.log("error", "s", "e1")
    agg.log("critical", "s", "e2")
    assert agg.error_burst("s", window_ns=10**12, threshold=2) is True
    assert agg.error_burst("s", window_ns=10**12, threshold=3) is False


def test_ring_bound():
    agg = lg.Aggregator(max_entries=5)
    for i in range(8):
        agg.log("info", "s", f"m{i}")
    assert len(agg._entries) == 5


def test_bad_level():
    import pytest

    agg = lg.Aggregator()
    with pytest.raises(lg.LogAggError):
        agg.log("bogus", "s", "m")


def test_stdlib_only():
    assert lg.stdlib_only() is True
