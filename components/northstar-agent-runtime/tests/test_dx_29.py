"""Tests for dx_29. migrations."""
import importlib.util, sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent

def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m

dx = _load("dx_29")

def _reg():
    r = dx.MigrationRegistry()
    r.register(1, "init")
    r.register(2, "add users")
    r.register(3, "add index")
    return r


def test_pending_order():
    assert _reg().pending(0) == [1, 2, 3]


def test_gap_rejected():
    r = _reg()
    with pytest.raises(dx.MigrateError):
        r.apply(2)


def test_apply_and_applied():
    r = _reg()
    r.apply(1)
    r.apply(2)
    assert r.applied() == [1, 2]
    assert r.pending(0) == [3]


def test_duplicate_rejected():
    r = _reg()
    with pytest.raises(dx.MigrateError):
        r.register(2, "dup")


def test_unknown_apply_raises():
    with pytest.raises(dx.MigrateError):
        _reg().apply(99)


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX29_MIGRATE_VERSION == "dx-migrate.v1"
