"""Runtime defense 17 tests."""

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


rd = _load("runtime_defense_17")


def test_within_limit():
    limits = rd.MemoryLimits(max_rss_mb=4096)
    assert rd.memory_exceeded(limits) in (False, None)


def test_tiny_limit_exceeded():
    limits = rd.MemoryLimits(max_rss_mb=1, soft_rss_mb=1)
    assert rd.memory_exceeded(limits) in (True, None)


def test_rejects_bad_config():
    with pytest.raises(rd.MemoryLimitError):
        rd.MemoryLimits(max_rss_mb=0)
    with pytest.raises(rd.MemoryLimitError):
        rd.MemoryLimits(max_rss_mb=100, soft_rss_mb=200)


def test_rss_readable():
    rss = rd.current_rss_mb()
    assert rss is None or (isinstance(rss, int) and rss >= 0)


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_17_VERSION == "runtime-defense-17.v1"
