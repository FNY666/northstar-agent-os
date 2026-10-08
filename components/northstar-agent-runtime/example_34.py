"""Example 34: ASI02 suite with session-risk tracking.
Modules demonstrated: asi02_probe + stateful_veto
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


a2 = _load("asi02_probe")
sv = _load("stateful_veto")
dv = _load("deterministic_veto")

state = sv.StatefulVeto()
BAD = ("evil", "rm -rf", "sudo", "os.system", "expand(")

def gate(tool, args):
    blocked = any(b in str(args).lower() for b in BAD)
    if blocked:
        state.record_deny("red-session", tool, dv.Consequence.IRREVERSIBLE_BROAD)
    return blocked

def run():
    summary = a2.run_all(gate)
    risk = state.risk_score("red-session")
    limited = state.should_rate_limit("red-session", "exec", dv.Consequence.IRREVERSIBLE_BROAD)
    return {"total": summary["total"], "blocked": summary["blocked"],
            "risk": risk, "limited": limited}

def main():
    r = run()
    assert r["total"] == 8
    assert r["blocked"] >= 6
    assert r["risk"] > 0
    print(f"example_34 OK: asi02 {r['blocked']}/8, session risk {r['risk']}")

if __name__ == "__main__":
    main()
