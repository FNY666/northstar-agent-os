"""Example 29: Per-hop schema plus per-hop confidence.
Modules demonstrated: hop_validation + confidence_gate
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


hv = _load("hop_validation")
cg = _load("confidence_gate")

schema = hv.HopSchema("h2", allowed_fields={"answer", "conf"}, required_fields={"answer", "conf"}, max_size=500)
conf = cg.ConfidenceGate()

def run():
    hops = [
        {"answer": "42", "conf": 95},
        {"answer": "maybe", "conf": 30},
    ]
    results = []
    for h in hops:
        valid = hv.validate_hop(h, schema)
        v = conf.check(valid["conf"])
        results.append((valid["answer"], v.action))
    return {"results": results}

def main():
    r = run()
    assert r["results"][0] == ("42", "allow")
    assert r["results"][1][1] in ("escalate", "deny")
    assert len(conf.history) == 2
    print("example_29 OK: hop validation + confidence")

if __name__ == "__main__":
    main()
