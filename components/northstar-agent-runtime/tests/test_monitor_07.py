"""Tests for monitor_07 (anomaly alerts)."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


an = _load("monitor_07")


def test_spike_detected():
    mon = an.AnomalyMonitor(window=10, z_threshold=3.0)
    for _ in range(10):
        assert mon.check("m", 0.05) is False
    assert mon.check("m", 9.0) is True


def test_stats_needs_data():
    import pytest

    d = an.Detector(window=5)
    d.observe(1.0)
    with pytest.raises(an.AnomalyError):
        d.stats()


def test_bad_detector_config():
    import pytest

    with pytest.raises(an.AnomalyError):
        an.Detector(window=1)
    with pytest.raises(an.AnomalyError):
        an.Detector(z_threshold=0)


def test_bad_metric_name():
    import pytest

    mon = an.AnomalyMonitor()
    with pytest.raises(an.AnomalyError):
        mon.check("", 1.0)


def test_stdlib_only():
    assert an.stdlib_only() is True
