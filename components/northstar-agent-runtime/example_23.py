"""Example 23: Tier-2 escalation feeds a deterministic veto.
Modules demonstrated: two_tier_gating + deterministic_veto
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
dv = _load("deterministic_veto")

veto = dv.DeterministicVeto()
veto.add_rule(dv.VetoRule("no-broad", dv.Consequence.IRREVERSIBLE_BROAD))

def tier2(tool, args):
    # Tier-2 maps the call to a consequence class; irreversible -> veto.
    if "drop" in str(args).lower():
        vetoed, reason = veto.check(dv.Consequence.IRREVERSIBLE_BROAD)
        return tt.TierVerdict("deny" if vetoed else "allow", reason, 0.95, 2, 1.0)
    return tt.TierVerdict("allow", "tier-2 clean", 0.2, 2, 1.0)

gate = tt.TwoTierGate(lambda t, a: 0.6, tier2, deny_threshold=0.95)

def run():
    v1 = gate.check("db", {"q": "drop table users"})
    v2 = gate.check("db", {"q": "select 1"})
    return {"v1": v1.decision, "v1_tier": v1.tier, "v2": v2.decision}

def main():
    r = run()
    assert r["v1"] == "deny" and r["v1_tier"] == 2
    assert r["v2"] == "allow"
    print("example_23 OK: two-tier + veto")

if __name__ == "__main__":
    main()
