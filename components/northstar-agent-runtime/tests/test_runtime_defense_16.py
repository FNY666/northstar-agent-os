"""Runtime defense 16 tests."""

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


rd = _load("runtime_defense_16")


def test_action_expiry():
    limits = rd.TimeLimits(max_action_seconds=10.0)
    assert rd.action_expired(11.0, limits) is True
    assert rd.action_expired(9.9, limits) is False


def test_task_expiry():
    limits = rd.TimeLimits(max_task_seconds=100.0)
    assert rd.task_expired(100.1, limits) is True
    assert rd.task_expired(50.0, limits) is False


def test_rejects_bad_config():
    with pytest.raises(rd.TimeLimitError):
        rd.TimeLimits(max_action_seconds=0)
    with pytest.raises(rd.TimeLimitError):
        rd.TimeLimits(max_action_seconds=100.0, max_task_seconds=50.0)


def test_rejects_negative_elapsed():
    limits = rd.TimeLimits()
    with pytest.raises(rd.TimeLimitError):
        rd.action_expired(-1.0, limits)


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_16_VERSION == "runtime-defense-16.v1"
