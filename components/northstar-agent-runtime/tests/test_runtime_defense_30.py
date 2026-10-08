"""Runtime defense 30 tests."""

import importlib.util
import sys
import time
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


rd = _load("runtime_defense_30")


def test_not_expired():
    d = rd.Deadline(rd.Timeout(10.0), started_at=100.0)
    assert d.expired(now=105.0) is False
    assert d.remaining(now=105.0) == 5.0


def test_expired():
    d = rd.Deadline(rd.Timeout(10.0), started_at=100.0)
    assert d.expired(now=110.1) is True
    assert d.remaining(now=110.1) == 0.0


def test_check_raises():
    d = rd.Deadline(rd.Timeout(1.0), started_at=0.0)
    with pytest.raises(rd.TimeoutError):
        d.check(now=5.0)


def test_scope_ok():
    with rd.timeout_scope(60.0):
        pass  # no raise


def test_scope_overrun():
    with pytest.raises(rd.TimeoutError):
        with rd.timeout_scope(0.000001):
            time.sleep(0.02)


def test_rejects_bad_timeout():
    with pytest.raises(rd.TimeoutError):
        rd.Timeout(0)
    with pytest.raises(rd.TimeoutError):
        rd.Timeout(-5.0)


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_30_VERSION == "runtime-defense-30.v1"
