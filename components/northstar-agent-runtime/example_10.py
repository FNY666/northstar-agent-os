"""Example 10: Unwaivable vetoes and human override.
Modules demonstrated: deterministic_veto (deep dive)
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


dv = _load("deterministic_veto")

veto = dv.DeterministicVeto()
veto.add_rule(dv.VetoRule("no-broad", dv.Consequence.IRREVERSIBLE_BROAD, unwaivable=True))
veto.add_rule(dv.VetoRule("no-scoped", dv.Consequence.IRREVERSIBLE_SCOPED, unwaivable=False))
# Model escalates: stricter, model cannot waive its own escalation.
veto.model_escalate(dv.VetoRule("model-no-high", dv.Consequence.REVERSIBLE_HIGH))

def run():
    v1, _ = veto.check(dv.Consequence.IRREVERSIBLE_BROAD)
    v2, _ = veto.check(dv.Consequence.IRREVERSIBLE_BROAD, human_override=True)
    v3, _ = veto.check(dv.Consequence.REVERSIBLE_HIGH)
    v4, _ = veto.check(dv.Consequence.REVERSIBLE_HIGH, human_override=True)
    v5, _ = veto.check(dv.Consequence.REVERSIBLE_LOW)
    return {"broad": v1, "broad_human": v2, "escalated": v3,
            "escalated_human": v4, "low": v5}

def main():
    r = run()
    assert r["broad"] is True
    assert r["broad_human"] is False
    assert r["escalated"] is True
    assert r["escalated_human"] is False
    assert r["low"] is False
    print("example_10 OK: veto semantics")

if __name__ == "__main__":
    main()
