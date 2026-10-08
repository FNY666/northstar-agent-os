"""Example 26: Command autonomy levels route to different gates.
Modules demonstrated: command_registry + two_tier_gating
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


cr = _load("command_registry")
tt = _load("two_tier_gating")

reg = cr.CommandRegistry()
reg.register(cr.CommandSpec("read", cr.AutonomyLevel.AUTOMATIC, "read file"))
reg.register(cr.CommandSpec("write", cr.AutonomyLevel.NOTIFY, "write file"))
reg.register(cr.CommandSpec("delete", cr.AutonomyLevel.APPROVAL_REQUIRED, "delete file"))

gate = tt.TwoTierGate(lambda t, a: 0.7 if t == "delete" else 0.1, deny_threshold=0.95)

def run():
    out = {}
    for cmd in ("read", "write", "delete"):
        v = gate.check(cmd, {})
        out[cmd] = (v.decision, v.tier)
    return {"gates": out, "registered": sorted(reg.commands())}

def main():
    r = run()
    assert r["gates"]["read"][0] == "allow"
    assert r["gates"]["delete"][1] == 2  # escalated to tier-2
    assert "delete" in r["registered"]
    print("example_26 OK: command registry + two-tier")

if __name__ == "__main__":
    main()
