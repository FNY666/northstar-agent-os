"""Example 09: Registered commands fire lifecycle hooks.
Modules demonstrated: command_registry + lifecycle_hooks
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
lh = _load("lifecycle_hooks")

reg = cr.CommandRegistry()
reg.register(cr.CommandSpec("read_file", cr.AutonomyLevel.AUTOMATIC, "read a file"))
reg.register(cr.CommandSpec("delete_file", cr.AutonomyLevel.APPROVAL_REQUIRED, "delete a file"))

hooks = lh.HookRegistry()
fired = []
hooks.register(lh.HookPoint.PRE_TOOL, lambda ctx: fired.append(ctx["tool"]))

def run():
    hooks.fire(lh.HookPoint.PRE_TOOL, {"tool": "read_file"})
    hooks.fire(lh.HookPoint.PRE_TOOL, {"tool": "delete_file"})
    return {"fired": fired, "commands": sorted(reg.commands())}

def main():
    r = run()
    assert r["fired"] == ["read_file", "delete_file"]
    assert "read_file" in r["commands"]
    assert "delete_file" in r["commands"]
    print("example_09 OK: command registry + hooks")

if __name__ == "__main__":
    main()
