"""Integration 09 tests."""

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


rd = _load("resource_defense")
tt = _load("two_tier_gating")
i09 = _load("integration_09")


def test_clean_allows_at_tier1():
    g = i09.ResourcedGate()
    v = g.check("read", {"path": "/x"})
    assert v.decision == "allow"
    assert v.tier == 1


def test_bomb_denied_at_tier1():
    g = i09.ResourcedGate()
    v = g.check("expand", {"input": "expand(" * 10})
    assert v.decision == "deny"
    assert v.tier == 1


def test_oversized_denied():
    g = i09.ResourcedGate()
    v = g.check("send", {"blob": "x" * 200000})
    assert v.decision == "deny"


def test_stats_tracked():
    g = i09.ResourcedGate()
    g.check("read", {"p": 1})
    assert g.stats["tier1"] >= 1


def test_version_pin():
    assert i09.INTEGRATION_09_VERSION == "integration-09.v1"
    assert i09.stdlib_only() is True
