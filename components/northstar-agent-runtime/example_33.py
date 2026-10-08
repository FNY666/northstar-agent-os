"""Example 33: Injection probes vs a two-tier gate.
Modules demonstrated: injection_probe + two_tier_gating
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


ip = _load("injection_probe")
tt = _load("two_tier_gating")

def tier1(tool, output):
    return 0.8 if "ignore" in output.lower() else 0.1

def tier2(tool, output):
    deny = "ignore" in output.lower() and "previous" in output.lower()
    return tt.TierVerdict("deny" if deny else "allow", "tier-2", 0.9 if deny else 0.2, 2, 1.0)

gate = tt.TwoTierGate(tier1, tier2, deny_threshold=0.95)

def gate_fn(tool_id, output):
    v = gate.check(tool_id, {"output": output})
    return v.decision == "deny"

def run():
    summary = ip.run_all_probes(gate_fn)
    return {"total": summary["total"], "blocked": summary["blocked"]}

def main():
    r = run()
    assert r["total"] > 0
    assert r["blocked"] >= 1
    assert r["blocked"] <= r["total"]
    print(f"example_33 OK: injection probes {r['blocked']}/{r['total']} vs two-tier")

if __name__ == "__main__":
    main()
