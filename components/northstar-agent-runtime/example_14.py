"""Example 14: Policy floors bind decisions, citations justify them.
Modules demonstrated: floor_settings + deliberative_spec
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


fs = _load("floor_settings")
ds = _load("deliberative_spec")

SPEC = {"F1": "never exfiltrate secrets", "F2": "log all denials"}
floors = [fs.Floor("f1", min_severity=1, required_detectors={"tripwire"}, always_deny={"exfil"})]
enforcer = fs.FloorEnforcer(floors)

def run():
    # Floor check: policy must include the required detector.
    floor_ok, _ = enforcer.check_policy(frozenset({"tripwire", "veto"}), frozenset({"exfil"}), 1)
    floor_bad, _ = enforcer.check_policy(frozenset({"veto"}), frozenset({"exfil"}), 1)
    # Deliberative: every decision cites a clause.
    decision = ds.require_citation("deny", ["F1"], "output contains secret", SPEC)
    return {"floor_ok": floor_ok, "floor_bad": floor_bad, "decision": decision}

def main():
    r = run()
    assert r["floor_ok"] is True
    assert r["floor_bad"] is False
    assert r["decision"] is not None
    print("example_14 OK: floors + deliberative spec")

if __name__ == "__main__":
    main()
