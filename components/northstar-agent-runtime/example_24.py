"""Example 24: Low confidence requires a spec citation.
Modules demonstrated: confidence_gate + deliberative_spec
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


cg = _load("confidence_gate")
ds = _load("deliberative_spec")

SPEC = {"C1": "verify before acting", "C2": "log denials"}
conf = cg.ConfidenceGate()

def decide(action_confidence, tool_risk="low"):
    v = conf.check(action_confidence, tool_risk=tool_risk)
    if v.action in ("escalate", "deny"):
        # Low confidence: must cite the spec clause being followed.
        d = ds.require_citation("deny", ["C1"], "confidence %d too low" % v.confidence, SPEC)
        return v.action, d
    return v.action, None

def run():
    a1, d1 = decide(95)
    a2, d2 = decide(40)
    a3, d3 = decide(10, tool_risk="high")
    return {"a1": a1, "a2": a2, "d2": d2, "a3": a3, "d3": d3}

def main():
    r = run()
    assert r["a1"] == "allow" and r["d1"] is None
    assert r["a2"] == "escalate" and r["d2"] is not None
    assert r["a3"] == "deny" and r["d3"] is not None
    print("example_24 OK: confidence + deliberative")

if __name__ == "__main__":
    main()
