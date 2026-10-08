"""Two-tier gating tests."""

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


tt = _load("two_tier_gating")


def test_tier1_allow():
    g = tt.TwoTierGate(lambda t, a: 0.1)
    v = g.check("tool", {})
    assert v.decision == "allow"
    assert v.tier == 1


def test_tier1_deny():
    g = tt.TwoTierGate(lambda t, a: 0.9)
    v = g.check("tool", {})
    assert v.decision == "deny"
    assert v.tier == 1


def test_escalate_to_tier2():
    def t2(t, a):
        return tt.TierVerdict("allow", "deep clean", 0.2, 2, 0)

    g = tt.TwoTierGate(lambda t, a: 0.6, t2)
    v = g.check("tool", {})
    assert v.tier == 2
    assert v.decision == "allow"


def test_no_tier2_fail_closed():
    g = tt.TwoTierGate(lambda t, a: 0.6, None)  # gray zone, no tier-2
    v = g.check("tool", {})
    assert v.decision == "deny"  # fail-closed


def test_tier1_exception_fail_closed():
    def bad(t, a):
        raise RuntimeError("oops")

    g = tt.TwoTierGate(bad)
    v = g.check("tool", {})
    assert v.decision == "deny"  # max suspicion


def test_stats():
    g = tt.TwoTierGate(lambda t, a: 0.1)
    g.check("t", {})
    g.check("t", {})
    assert g.stats["tier1"] == 2
    assert g.stats["tier2"] == 0


def test_stdlib_only():
    assert tt.stdlib_only() is True


def test_version_pin():
    assert tt.TWO_TIER_VERSION == "two-tier-gating.v1"
