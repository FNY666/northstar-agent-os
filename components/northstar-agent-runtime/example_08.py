"""Example 08: Two-tier gate with confidence escalation.
Modules demonstrated: two_tier_gating + confidence_gate
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, _HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


tt = _load("two_tier_gating")
cg = _load("confidence_gate")

def tier1(tool, args):
    return 0.9 if "secret" in str(args).lower() else 0.1

def tier2(tool, args):
    return tt.TierVerdict("deny", "tier-2: secrets access", 0.95, 2, 1.0)

gate = tt.TwoTierGate(tier1, tier2, deny_threshold=0.95)
conf = cg.ConfidenceGate()

def run():
    v1 = gate.check("read", {"file": "public.txt"})
    v2 = gate.check("read", {"file": "secret.txt"})
    c1 = conf.check(95, tool_risk="low")
    c2 = conf.check(30, tool_risk="high")
    return {"v1": v1.decision, "v1_tier": v1.tier,
            "v2": v2.decision, "v2_tier": v2.tier,
            "c1": c1.action, "c2": c2.action}

def main():
    r = run()
    assert r["v1"] == "allow" and r["v1_tier"] == 1
    assert r["v2"] == "deny" and r["v2_tier"] == 2
    assert r["c1"] == "allow"
    assert r["c2"] == "deny"
    print("example_08 OK: two-tier + confidence")

if __name__ == "__main__":
    main()
