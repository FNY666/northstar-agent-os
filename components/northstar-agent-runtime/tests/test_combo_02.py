"""Tests for combo_02 (Trusted chain)."""

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


combo = _load("combo_02")


def _chain():
    tp = combo.tp
    registry = tp.ToolRegistry()
    definition = {"name": "read", "version": "1.0"}
    registry.pin("read", definition, pinned_by="t")
    schema = combo.hv.HopSchema("h", frozenset({"path"}), frozenset({"path"}))
    policy = {"read": {"allowed_sources": {"read"}}}
    return combo.TrustedChain(registry, schema, policy), definition


def test_valid_step():
    chain, definition = _chain()
    s = chain.step("read", definition, "v", {"path": "/x"})
    assert "path" in s["hop"]


def test_tampered_definition_fails():
    chain, _ = _chain()
    try:
        chain.step("read", {"name": "read", "version": "2"}, "v", {"path": "/x"})
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_bad_hop_fails():
    chain, definition = _chain()
    try:
        chain.step("read", definition, "v", {"wrong": 1})
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_chain_combines_provenance():
    chain, definition = _chain()
    s1 = chain.step("read", definition, "a", {"path": "/a"})
    s2 = chain.step("read", definition, "b", {"path": "/b"})
    combined = chain.chain([s1, s2])
    assert "read" in set(combined.deps)


def test_stdlib_only():
    assert combo.stdlib_only() is True
