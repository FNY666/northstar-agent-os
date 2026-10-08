"""Example 25: Canary probes plus session-rate limiting.
Modules demonstrated: lifecycle_hooks + stateful_veto
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


lh = _load("lifecycle_hooks")
sv = _load("stateful_veto")
dv = _load("deterministic_veto")

hooks = lh.HookRegistry()
calls = []
hooks.register(lh.HookPoint.PRE_TOOL, lambda ctx: calls.append(ctx["tool"]) or True)
state = sv.StatefulVeto()

def run():
    # Canary self-test before the session starts.
    probe = lh.CanaryProbe("c1", "read", {"path": "/tmp/x"}, "read canary")
    canary = hooks.run_canary(probe)
    # Session: repeated denials raise risk and trigger rate limiting.
    s = "sess-9"
    state.record_deny(s, "exec", dv.Consequence.IRREVERSIBLE_BROAD)
    state.record_deny(s, "exec", dv.Consequence.IRREVERSIBLE_BROAD)
    risk = state.risk_score(s)
    limited = state.should_rate_limit(s, "exec", dv.Consequence.IRREVERSIBLE_BROAD)
    hooks.fire(lh.HookPoint.PRE_TOOL, {"tool": "read"})
    return {"canary": canary, "risk": risk, "limited": limited, "calls": calls}

def main():
    r = run()
    assert r["canary"] is not None
    assert r["risk"] > 0
    assert r["calls"] == ["read"]
    print("example_25 OK: hooks + stateful veto")

if __name__ == "__main__":
    main()
