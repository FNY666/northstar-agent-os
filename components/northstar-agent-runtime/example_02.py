"""Example 02: Tripwire halts on evil patterns, veto blocks irreversible.
Modules demonstrated: tripwire_guardrails + deterministic_veto
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


tw = _load("tripwire_guardrails")
dv = _load("deterministic_veto")

guard = tw.TripwireGuard(
    "no-destruct",
    lambda tool, args: any(b in str(args).lower() for b in ("rm -rf", "evil", "sudo")),
    on_violation=tw.TripwireOutcome.HALT,
)
veto = dv.DeterministicVeto()
veto.add_rule(dv.VetoRule("no-broad", dv.Consequence.IRREVERSIBLE_BROAD))

def run():
    evil = guard.check("exec", {"cmd": "rm -rf /"})
    benign = guard.check("read", {"path": "/tmp/a"})
    vetoed, _ = veto.check(dv.Consequence.IRREVERSIBLE_BROAD)
    readable, _ = veto.check(dv.Consequence.REVERSIBLE_LOW)
    return {"evil_halted": evil.outcome == tw.TripwireOutcome.HALT,
            "benign_allowed": benign.outcome == tw.TripwireOutcome.ALLOW,
            "broad_vetoed": vetoed, "read_allowed": not readable}

def main():
    r = run()
    assert r["evil_halted"] is True
    assert r["benign_allowed"] is True
    assert r["broad_vetoed"] is True
    assert r["read_allowed"] is True
    assert guard.fired_count == 1
    print("example_02 OK: tripwire + veto")

if __name__ == "__main__":
    main()
