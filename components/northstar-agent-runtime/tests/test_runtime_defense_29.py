"""Runtime defense 29 tests."""

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


rd = _load("runtime_defense_29")


def test_acquire_release():
    bh = rd.Bulkhead(rd.BulkheadConfig(partitions={"a": 2}))
    bh.acquire("a")
    assert bh.available("a") == 1
    bh.release("a")
    assert bh.available("a") == 2


def test_exhaustion_isolated():
    bh = rd.Bulkhead(rd.BulkheadConfig(partitions={"a": 1, "b": 1}))
    bh.acquire("a")
    with pytest.raises(rd.BulkheadError):
        bh.acquire("a")
    bh.acquire("b")  # b unaffected
    assert bh.available("b") == 0


def test_unknown_partition():
    bh = rd.Bulkhead(rd.BulkheadConfig(partitions={"a": 1}))
    with pytest.raises(rd.BulkheadError):
        bh.acquire("ghost")
    with pytest.raises(rd.BulkheadError):
        bh.release("ghost")


def test_release_never_negative():
    bh = rd.Bulkhead(rd.BulkheadConfig(partitions={"a": 1}))
    bh.release("a")
    assert bh.available("a") == 1


def test_rejects_bad_config():
    with pytest.raises(rd.BulkheadError):
        rd.BulkheadConfig(partitions={})
    with pytest.raises(rd.BulkheadError):
        rd.BulkheadConfig(partitions={"a": 0})


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RUNTIME_DEFENSE_29_VERSION == "runtime-defense-29.v1"
