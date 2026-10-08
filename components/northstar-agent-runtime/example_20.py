"""Example 20: ASI02 suite vs resource-exhaustion limits.
Modules demonstrated: asi02_probe + resource_defense
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
rd = _load("resource_defense")

# The asi02-005 recursive bomb is only 3 deep, so set a strict bound.
limits = rd.ResourceLimits(max_nesting_depth=2, max_repeated_calls=8)

def gate(tool, args):
    ok, _ = rd.check_resources(tool, args, limits)
    return not ok

def run():
    summary = a2.run_all(gate)
    return {"total": summary["total"], "blocked": summary["blocked"],
            "rate": summary["block_rate"]}

def main():
    r = run()
    assert r["total"] == 8
    # Resource limits catch the recursive bomb at minimum.
    assert r["blocked"] >= 1
    # Direct check: the asi02-005 bomb shape is caught by these limits.
    ok, _ = rd.check_resources("expand", {"input": "expand(expand(expand(x)))"}, limits)
    assert ok is False
    print(f"example_20 OK: asi02 vs resources {r['blocked']}/{r['total']}")

if __name__ == "__main__":
    main()
