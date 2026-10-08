"""Example 36: Lifecycle hook fires on tool-definition drift.
Modules demonstrated: tool_pinning + lifecycle_hooks
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
lh = _load("lifecycle_hooks")

reg = tp.ToolRegistry()
reg.pin("search", {"v": "1.0"}, pinned_by="admin")

hooks = lh.HookRegistry()
alerts = []
hooks.register(lh.HookPoint.PRE_TOOL,
               lambda ctx: alerts.append(ctx["tool"]) or False
               if ctx.get("drift") else True)

def call(tool_id, definition, args):
    drifted = not reg.verify(tool_id, definition)
    # A False return from any hook blocks the call.
    allowed = hooks.fire(lh.HookPoint.PRE_TOOL, {"tool": tool_id, "drift": drifted})
    return "deny: drift" if drifted else ("blocked" if not allowed else "allow")

def run():
    r1 = call("search", {"v": "1.0"}, {"q": "x"})
    r2 = call("search", {"v": "2.0"}, {"q": "x"})
    return {"r1": r1, "r2": r2, "alerts": alerts}

def main():
    r = run()
    assert r["r1"] == "allow"
    assert r["r2"] == "deny: drift"
    assert r["alerts"] == ["search"]
    print("example_36 OK: pinning + lifecycle hooks")

if __name__ == "__main__":
    main()
