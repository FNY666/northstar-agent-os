"""Runtime defense 23 tests."""

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


rd = _load("runtime_defense_23")


def test_append_and_chain():
    log = rd.AuditLog()
    r1 = log.append("a", {"x": 1})
    r2 = log.append("b", {"x": 2})
    assert r1.seq == 0 and r2.seq == 1
    assert r2.prev_hash == r1.record_hash
    assert log.verify_chain() is True


def test_tamper_detected():
    log = rd.AuditLog()
    log.append("a", {"x": 1})
    # Mutate the details dict in place (simulates tamper).
    log.records[0].details["x"] = 999
    assert log.verify_chain() is False


def test_rejects_empty_event():
    log = rd.AuditLog()
    with pytest.raises(rd.AuditError):
        log.append("")


def test_empty_log_verifies():
    assert rd.AuditLog().verify_chain() is True


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_23_VERSION == "runtime-defense-23.v1"
