"""Example 28: Policy floors bound the tripwire configuration.
Modules demonstrated: floor_settings + tripwire_guardrails
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
tw = _load("tripwire_guardrails")

floors = [fs.Floor("f1", min_severity=1, required_detectors={"tripwire"}, always_deny=set())]
enforcer = fs.FloorEnforcer(floors)

def make_guard(detectors):
    ok, _ = enforcer.check_policy(frozenset(detectors), frozenset(), 1)
    if not ok:
        raise fs.FloorError("policy weakens floor")
    return tw.TripwireGuard("g", lambda t, a: "evil" in str(a).lower())

def run():
    g = make_guard(["tripwire"])
    r1 = g.check("x", {"q": "hello"})
    r2 = g.check("x", {"q": "evil"})
    try:
        make_guard(["veto"])  # missing required detector
        weak_ok = True
    except fs.FloorError:
        weak_ok = False
    return {"r1": r1.outcome, "r2": r2.outcome, "weak_rejected": not weak_ok}

def main():
    r = run()
    assert r["r1"] == tw.TripwireOutcome.ALLOW
    assert r["r2"] == tw.TripwireOutcome.HALT
    assert r["weak_rejected"] is True
    print("example_28 OK: floors + tripwire")

if __name__ == "__main__":
    main()
