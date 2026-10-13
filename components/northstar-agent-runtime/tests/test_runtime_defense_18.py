"""Runtime defense 18 tests."""

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


rd = _load("runtime_defense_18")


def test_within_limit():
    limits = rd.CpuLimits(max_cpu_seconds=3600.0)
    assert rd.cpu_exceeded(rd.current_cpu_seconds(), limits) is False


def test_exceeded():
    limits = rd.CpuLimits(max_cpu_seconds=10.0, soft_cpu_seconds=5.0)
    assert rd.cpu_exceeded(10.1, limits) is True
    assert rd.cpu_exceeded(9.9, limits) is False


def test_rejects_bad_config():
    with pytest.raises(rd.CpuLimitError):
        rd.CpuLimits(max_cpu_seconds=0)
    with pytest.raises(rd.CpuLimitError):
        rd.CpuLimits(max_cpu_seconds=10.0, soft_cpu_seconds=20.0)


def test_rejects_negative():
    with pytest.raises(rd.CpuLimitError):
        rd.cpu_exceeded(-1.0, rd.CpuLimits())


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_18_VERSION == "runtime-defense-18.v1"
