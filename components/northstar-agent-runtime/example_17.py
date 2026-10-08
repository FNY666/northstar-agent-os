"""Example 17: Goal loop with forensic snapshots per cycle.
Modules demonstrated: goal_comparator + task_snapshot
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


gc = _load("goal_comparator")
ts = _load("task_snapshot")

def run():
    comp = gc.GoalComparator("count to 3",
        comparator_fn=lambda obj, s: s.get("count", 0) >= 3)
    snaps = []
    count = 0
    while True:
        count += 1
        snap = ts.TaskSnapshot(f"s{count}", "count", {"model": "x"})
        snap.add_tool_call("increment", {"n": count}, count, "allow")
        snaps.append(snap)
        r = comp.check({"count": count})
        if r.done:
            break
    return {"cycles": comp.cycles_used, "snaps": len(snaps),
            "hashes": [s.snapshot_hash() for s in snaps]}

def main():
    r = run()
    assert r["cycles"] == 3
    assert r["snaps"] == 3
    assert all(h.startswith("sha256:") for h in r["hashes"])
    assert len(set(r["hashes"])) == 3
    print("example_17 OK: goal comparator + snapshots")

if __name__ == "__main__":
    main()
