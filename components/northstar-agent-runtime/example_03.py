"""Example 03: Red-team injection probes vs a spotlighting gate.
Modules demonstrated: injection_probe + spotlighting
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
spot = _load("spotlighting")

def gate(tool_id, output):
    # Spotlight the output; block if smuggled instruction survives.
    marked, _ = spot.spotlight(output, level="datamark")
    low = marked.lower()
    return "ignore previous" in low or "system:" in low

def run():
    summary = ip.run_all_probes(gate)
    return {"total": summary["total"], "blocked": summary["blocked"],
            "rate": summary["block_rate"]}

def main():
    r = run()
    assert r["total"] > 0
    assert r["blocked"] >= 1
    assert 0.0 <= r["rate"] <= 1.0
    print(f"example_03 OK: injection probes {r['blocked']}/{r['total']} blocked")

if __name__ == "__main__":
    main()
