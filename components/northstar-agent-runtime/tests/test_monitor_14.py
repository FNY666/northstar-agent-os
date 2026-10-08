"""Tests for monitor_14 (behavioral baselines)."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


bb = _load("monitor_14")


def test_establish_and_drift():
    s = bb.BaselineStore(min_observations=5)
    for _ in range(5):
        s.observe("a", "m", 10.0)
    assert s.established("a", "m") is True
    assert s.drift("a", "m", 10.0) == 0.0


def test_drift_before_established():
    import pytest

    s = bb.BaselineStore(min_observations=5)
    s.observe("a", "m", 1.0)
    with pytest.raises(bb.BaselineError):
        s.drift("a", "m", 1.0)


def test_unknown_baseline():
    import pytest

    s = bb.BaselineStore()
    with pytest.raises(bb.BaselineError):
        s.drift("nobody", "m", 1.0)


def test_bad_value():
    import pytest

    s = bb.BaselineStore()
    with pytest.raises(bb.BaselineError):
        s.observe("a", "m", float("nan"))


def test_stdlib_only():
    assert bb.stdlib_only() is True
