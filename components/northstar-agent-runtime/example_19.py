"""Example 19: Injection probes vs deterministic veto on tool calls.
Modules demonstrated: injection_probe + deterministic_veto
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


ip = _load("injection_probe")
dv = _load("deterministic_veto")

veto = dv.DeterministicVeto()
veto.add_rule(dv.VetoRule("no-broad", dv.Consequence.IRREVERSIBLE_BROAD))

# Gate: map poisoned outputs to a consequence class, veto if irreversible.
def gate(tool_id, output):
    low = output.lower()
    if any(b in low for b in ("rm -rf", "drop table", "delete")):
        vetoed, _ = veto.check(dv.Consequence.IRREVERSIBLE_BROAD)
        return vetoed
    return False

def run():
    summary = ip.run_all_probes(gate)
    return {"total": summary["total"], "blocked": summary["blocked"]}

def main():
    r = run()
    assert r["total"] > 0
    assert r["blocked"] >= 1
    # A benign output is never vetoed.
    vetoed, _ = veto.check(dv.Consequence.REVERSIBLE_LOW)
    assert vetoed is False
    print(f"example_19 OK: injection probes {r['blocked']}/{r['total']} vetoed")

if __name__ == "__main__":
    main()
