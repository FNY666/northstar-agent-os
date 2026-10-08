"""Example 38: Snapshots record provenance of every tool call.
Modules demonstrated: task_snapshot + provenance_tagging
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


ts = _load("task_snapshot")
prov = _load("provenance_tagging")

def run():
    snap = ts.TaskSnapshot("s-prob", "summarize", {"model": "x"})
    t1 = prov.tag_user("summarize this")
    t2 = prov.tag_tool_output("the report says up", "web_search")
    snap.add_tool_call("read", {"q": t1.value}, "doc", "allow")
    snap.add_tool_call("search", {"q": t2.value}, "result", "allow")
    snap.gate_decisions.append({"tool": "search", "provenance": list(t2.deps)})
    h = snap.snapshot_hash()
    return {"calls": len(snap.tool_calls), "hash": h,
            "prov": snap.gate_decisions[0]["provenance"]}

def main():
    r = run()
    assert r["calls"] == 2
    assert r["hash"].startswith("sha256:")
    assert "web_search" in r["prov"]
    print("example_38 OK: snapshots + provenance")

if __name__ == "__main__":
    main()
