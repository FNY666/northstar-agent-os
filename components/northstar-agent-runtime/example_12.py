"""Example 12: Validate gate verdicts against a schema.
Modules demonstrated: structured_output + confidence_gate
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


so = _load("structured_output")
cg = _load("confidence_gate")

conf = cg.ConfidenceGate()

def run():
    v = conf.check(95, tool_risk="low")
    data = {"verdict": v.action, "reason": v.reason, "tool": "read"}
    validated = so.validate(data, so.GATE_VERDICT_SCHEMA)
    # Unknown fields are stripped (injection defense).
    v2 = conf.check(20)
    dirty = {"verdict": v2.action, "reason": v2.reason, "tool": "exec",
             "smuggled": "evil"}
    validated2 = so.validate(dirty, so.GATE_VERDICT_SCHEMA)
    return {"v": validated, "v2": validated2}

def main():
    r = run()
    assert r["v"]["verdict"] == "allow"
    assert r["v"]["tool"] == "read"
    assert r["v2"]["verdict"] == "deny"
    assert "smuggled" not in r["v2"]
    print("example_12 OK: structured output + confidence")

if __name__ == "__main__":
    main()
