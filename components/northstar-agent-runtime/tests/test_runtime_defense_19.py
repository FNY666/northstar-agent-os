"""Runtime defense 19 tests."""

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


rd = _load("runtime_defense_19")


def test_within_quota():
    limits = rd.DiskLimits(max_write_bytes=1000, max_single_write_bytes=1000)
    ledger = rd.WriteLedger()
    ledger.record(400, limits)
    ledger.record(400, limits)
    assert ledger.bytes_written == 800


def test_quota_exceeded():
    limits = rd.DiskLimits(max_write_bytes=1000, max_single_write_bytes=1000)
    ledger = rd.WriteLedger()
    ledger.record(900, limits)
    with pytest.raises(rd.DiskLimitError):
        ledger.record(200, limits)


def test_single_write_too_big():
    limits = rd.DiskLimits(max_write_bytes=1000, max_single_write_bytes=100)
    ledger = rd.WriteLedger()
    with pytest.raises(rd.DiskLimitError):
        ledger.record(101, limits)


def test_rejects_bad_config():
    with pytest.raises(rd.DiskLimitError):
        rd.DiskLimits(max_write_bytes=0)
    with pytest.raises(rd.DiskLimitError):
        rd.DiskLimits(max_write_bytes=10, max_single_write_bytes=20)


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_19_VERSION == "runtime-defense-19.v1"
