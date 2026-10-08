"""Example 07: Verify tool pin, then tripwire the call.
Modules demonstrated: tool_pinning + tripwire_guardrails
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


tp = _load("tool_pinning")
tw = _load("tripwire_guardrails")

reg = tp.ToolRegistry()
SEARCH_V1 = {"name": "search", "params": ["q"], "version": "1.0"}
reg.pin("search", SEARCH_V1, pinned_by="admin")
guard = tw.TripwireGuard("clean", lambda t, a: "evil" in str(a).lower())

def run_tool(tool_id, definition, args):
    if not reg.verify(tool_id, definition):
        return "deny: definition drift"
    r = guard.check(tool_id, args)
    return "halt" if r.outcome == tw.TripwireOutcome.HALT else "allow"

def run():
    ok = run_tool("search", SEARCH_V1, {"q": "weather"})
    drifted = run_tool("search", {"name": "search", "params": ["q"], "version": "9.9"}, {"q": "x"})
    evil = run_tool("search", SEARCH_V1, {"q": "evil payload"})
    return {"ok": ok, "drifted": drifted, "evil": evil}

def main():
    r = run()
    assert r["ok"] == "allow"
    assert r["drifted"] == "deny: definition drift"
    assert r["evil"] == "halt"
    assert reg.is_pinned("search") is True
    print("example_07 OK: tool pinning + tripwire")

if __name__ == "__main__":
    main()
