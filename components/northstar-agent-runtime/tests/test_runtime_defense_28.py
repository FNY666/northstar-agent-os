"""Runtime defense 28 tests."""

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


rd = _load("runtime_defense_28")


def test_opens_after_threshold():
    cb = rd.CircuitBreaker("x", failure_threshold=3, cooldown_seconds=100.0)
    cb.record_failure(now=0.0)
    cb.record_failure(now=0.0)
    assert cb.allow(now=0.0) is True
    cb.record_failure(now=0.0)
    assert cb.allow(now=0.0) is False
    assert cb.state == rd.CircuitState.OPEN


def test_half_open_after_cooldown():
    cb = rd.CircuitBreaker("x", failure_threshold=1, cooldown_seconds=10.0)
    cb.record_failure(now=0.0)
    assert cb.allow(now=5.0) is False
    assert cb.allow(now=11.0) is True
    assert cb.state == rd.CircuitState.HALF_OPEN


def test_success_closes():
    cb = rd.CircuitBreaker("x", failure_threshold=1, cooldown_seconds=100.0)
    cb.record_failure(now=0.0)
    cb.record_success()
    assert cb.state == rd.CircuitState.CLOSED
    assert cb.consecutive_failures == 0


def test_half_open_probe_failure_reopens():
    cb = rd.CircuitBreaker("x", failure_threshold=1, cooldown_seconds=10.0)
    cb.record_failure(now=0.0)
    assert cb.allow(now=11.0) is True  # half-open probe
    cb.record_failure(now=12.0)
    assert cb.allow(now=13.0) is False


def test_rejects_bad_config():
    with pytest.raises(rd.CircuitBreakerError):
        rd.CircuitBreaker("", failure_threshold=1)
    with pytest.raises(rd.CircuitBreakerError):
        rd.CircuitBreaker("x", failure_threshold=0)


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_28_VERSION == "runtime-defense-28.v1"
