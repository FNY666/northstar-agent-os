"""Runtime defense 25 tests."""

import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


rd = _load("runtime_defense_25")


def _seed():
    # Baseline with realistic variance (mean 10.0, std ~0.28).
    return [10.0 + ((i * 7) % 5 - 2) * 0.2 for i in range(20)]


def test_normal_not_flagged():
    det = rd.AnomalyDetector()
    det.seed(_seed())
    anomalous, _ = det.check(10.5)
    assert anomalous is False


def test_spike_flagged():
    det = rd.AnomalyDetector()
    det.seed(_seed())
    anomalous, z = det.check(100.0)
    assert anomalous is True
    assert z > 3.0


def test_anomaly_not_adopted():
    det = rd.AnomalyDetector()
    det.seed(_seed())
    det.check(1000.0)  # anomaly
    anomalous, _ = det.check(10.1)  # baseline intact
    assert anomalous is False


def test_rejects_short_seed():
    with pytest.raises(rd.AnomalyError):
        rd.AnomalyDetector().seed([1.0])


def test_rejects_bad_config():
    with pytest.raises(rd.AnomalyError):
        rd.AnomalyConfig(z_threshold=0)


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_25_VERSION == "runtime-defense-25.v1"
