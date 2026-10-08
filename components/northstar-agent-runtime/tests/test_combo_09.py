"""Tests for combo_09 (Provenance output guard)."""

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


combo = _load("combo_09")


def test_guard_masks_pii():
    g = combo.ProvenanceOutputGuard()
    r = g.guard("t", "mail me at zed@example.com please")
    assert "zed@example.com" not in r["masked"]


def test_spotlight_marks():
    g = combo.ProvenanceOutputGuard()
    r = g.guard("t", "hello")
    assert r["nonce"] in r["marked"]


def test_provenance_tagged():
    g = combo.ProvenanceOutputGuard()
    r = g.guard("toolA", "v")
    assert "toolA" in set(r["tagged"].deps)


def test_policy_checked():
    g = combo.ProvenanceOutputGuard()
    ok = g.guard("t", "v", {"t": {"allowed_sources": {"t"}}})
    assert ok["policy_ok"] is True
    bad = g.guard("t", "v", {"t": {"allowed_sources": {"user"}}})
    assert bad["policy_ok"] is False


def test_stdlib_only():
    assert combo.stdlib_only() is True
