"""Tests for combo_11 (Replayable audit)."""

import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


combo = _load("combo_11")


def test_record_ok():
    a = combo.ReplayableAudit()
    r = a.record("r", "read", {"p": 1}, "res", "allow")
    assert r["calls"] == 1
    assert r["snapshot_hash"].startswith("sha256:")


def test_missing_reasoning_fails():
    a = combo.ReplayableAudit()
    try:
        a.record(None, "read", {}, "x", "allow")
    except combo.it.InterleavedError:
        return
    raise AssertionError("expected InterleavedError")


def test_combined_provenance():
    a = combo.ReplayableAudit()
    a.record("r1", "t1", {}, "x", "allow")
    a.record("r2", "t2", {}, "y", "allow")
    c = a.combined_provenance()
    assert {"t1", "t2"} <= set(c.deps)


def test_empty_combine_fails():
    a = combo.ReplayableAudit()
    try:
        a.combined_provenance()
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_stdlib_only():
    assert combo.stdlib_only() is True
