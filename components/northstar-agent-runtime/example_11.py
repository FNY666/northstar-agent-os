"""Example 11: Session risk rises across repeated denials.
Modules demonstrated: stateful_veto + two_tier_gating
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


sv = _load("stateful_veto")
tt = _load("two_tier_gating")
dv = _load("deterministic_veto")

state = sv.StatefulVeto()
gate = tt.TwoTierGate(lambda t, a: 0.9 if "secret" in str(a) else 0.05,
                      deny_threshold=0.95)

def attempt(session, tool, args):
    v = gate.check(tool, args)
    if v.decision == "deny":
        state.record_deny(session, tool, dv.Consequence.REVERSIBLE_HIGH)
    return v.decision

def run():
    s = "sess-1"
    r1 = attempt(s, "read", {"f": "secret.txt"})
    r2 = attempt(s, "read", {"f": "secret.txt"})
    risk = state.risk_score(s)
    limited = state.should_rate_limit(s, "read", dv.Consequence.REVERSIBLE_HIGH)
    clean = state.risk_score("sess-2")
    return {"r1": r1, "r2": r2, "risk": risk, "limited": limited, "clean": clean}

def main():
    r = run()
    assert r["r1"] == "deny" and r["r2"] == "deny"
    assert r["risk"] > r["clean"]
    assert r["clean"] == 0 or r["clean"] < r["risk"]
    print(f"example_11 OK: session risk {r['risk']} > {r['clean']}")

if __name__ == "__main__":
    main()
