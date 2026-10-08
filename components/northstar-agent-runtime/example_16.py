"""Example 16: Recursion bombs: resource defense behind the tripwire.
Modules demonstrated: resource_defense + tripwire_guardrails
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


rd = _load("resource_defense")
tw = _load("tripwire_guardrails")

guard = tw.TripwireGuard(
    "res-gate",
    lambda tool, args: not rd.check_resources(tool, args)[0],
    on_violation=tw.TripwireOutcome.HALT,
)

def run():
    bomb = {"input": "expand(" * 8 + "x" + ")" * 8}
    r_bomb = guard.check("expand", bomb)
    r_ok = guard.check("read", {"path": "/tmp/x"})
    ok, reason = rd.check_resources("expand", bomb)
    return {"bomb_halted": r_bomb.outcome == tw.TripwireOutcome.HALT,
            "ok_allowed": r_ok.outcome == tw.TripwireOutcome.ALLOW,
            "reason": reason}

def main():
    r = run()
    assert r["bomb_halted"] is True
    assert r["ok_allowed"] is True
    assert "nesting" in r["reason"]
    print("example_16 OK: resource defense + tripwire")

if __name__ == "__main__":
    main()
