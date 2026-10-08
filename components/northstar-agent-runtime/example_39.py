"""Example 39: Cited decisions pass through the tripwire.
Modules demonstrated: deliberative_spec + tripwire_guardrails
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


ds = _load("deliberative_spec")
tw = _load("tripwire_guardrails")

SPEC = {"A1": "allow benign reads", "A2": "deny destructive commands"}
guard = tw.TripwireGuard("g", lambda t, a: "rm -rf" in str(a).lower())

def decide(tool, args, clause, reasoning):
    r = guard.check(tool, args)
    if r.outcome != tw.TripwireOutcome.ALLOW:
        return "deny", ds.require_citation("deny", ["A2"], reasoning, SPEC)
    return "allow", ds.require_citation("allow", [clause], reasoning, SPEC)

def run():
    d1, c1 = decide("read", {"p": "/x"}, "A1", "benign read per A1")
    d2, c2 = decide("exec", {"cmd": "rm -rf /"}, "A2", "destructive per A2")
    return {"d1": d1, "d2": d2, "c1": c1, "c2": c2}

def main():
    r = run()
    assert r["d1"] == "allow" and r["c1"] is not None
    assert r["d2"] == "deny" and r["c2"] is not None
    # Missing citation is rejected.
    try:
        ds.require_citation("allow", [], "no clause", SPEC)
        cited = True
    except ds.DeliberativeError:
        cited = False
    assert cited is False
    print("example_39 OK: deliberative + tripwire")

if __name__ == "__main__":
    main()
