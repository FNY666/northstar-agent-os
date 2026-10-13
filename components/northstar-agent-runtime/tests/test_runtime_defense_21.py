"""Runtime defense 21 tests."""

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


rd = _load("runtime_defense_21")


def test_within_budget():
    limits = rd.FdLimits(max_fds=3)
    ledger = rd.FdLedger()
    for _ in range(3):
        ledger.open(limits)
    assert ledger.open_count == 3


def test_budget_exhausted():
    limits = rd.FdLimits(max_fds=1)
    ledger = rd.FdLedger()
    ledger.open(limits)
    with pytest.raises(rd.FdLimitError):
        ledger.open(limits)


def test_close_frees_slot():
    limits = rd.FdLimits(max_fds=1)
    ledger = rd.FdLedger()
    ledger.open(limits)
    ledger.close()
    ledger.open(limits)  # ok now
    assert ledger.open_count == 1


def test_rejects_bad_config():
    with pytest.raises(rd.FdLimitError):
        rd.FdLimits(max_fds=0)


def test_system_limit_shape():
    rlim = rd.system_fd_limit()
    assert rlim is None or (rlim[1] >= rlim[0] > 0)


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_21_VERSION == "runtime-defense-21.v1"
