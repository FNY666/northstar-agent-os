"""Runtime defense 20 tests."""

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


rd = _load("runtime_defense_20")


def test_within_budget():
    limits = rd.ProcessLimits(max_processes=4)
    ledger = rd.SpawnLedger()
    for _ in range(4):
        ledger.spawn(limits)
    assert ledger.spawned == 4


def test_budget_exhausted():
    limits = rd.ProcessLimits(max_processes=1)
    ledger = rd.SpawnLedger()
    ledger.spawn(limits)
    with pytest.raises(rd.ProcessLimitError):
        ledger.spawn(limits)


def test_depth_exceeded():
    limits = rd.ProcessLimits(max_depth=2)
    ledger = rd.SpawnLedger()
    with pytest.raises(rd.ProcessLimitError):
        ledger.spawn(limits, depth=3)


def test_rejects_bad_config():
    with pytest.raises(rd.ProcessLimitError):
        rd.ProcessLimits(max_processes=0)
    with pytest.raises(rd.ProcessLimitError):
        rd.ProcessLimits(max_depth=0)


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_20_VERSION == "runtime-defense-20.v1"
