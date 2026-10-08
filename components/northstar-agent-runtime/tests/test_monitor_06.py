"""Tests for monitor_06 (trace sampling)."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


ts = _load("monitor_06")
TID = "cd" * 16


def test_always():
    assert ts.AlwaysOn().should_sample(TID) is True
    assert ts.AlwaysOff().should_sample(TID) is False


def test_probability_edges_and_deterministic():
    assert ts.Probability(0.0).should_sample(TID) is False
    assert ts.Probability(1.0).should_sample(TID) is True
    p = ts.Probability(0.5)
    assert p.should_sample(TID) == p.should_sample(TID)


def test_rate_limiting():
    rl = ts.RateLimiting(2)
    assert rl.should_sample(TID) is True
    assert rl.should_sample(TID) is True
    assert rl.should_sample(TID) is False


def test_bad_inputs():
    import pytest

    with pytest.raises(ts.SamplingError):
        ts.Probability(2.0)
    with pytest.raises(ts.SamplingError):
        ts.RateLimiting(0)
    with pytest.raises(ts.SamplingError):
        ts.AlwaysOn().should_sample("bad")


def test_stdlib_only():
    assert ts.stdlib_only() is True
