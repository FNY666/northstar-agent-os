"""Example 30: Reasoning is logged, decisions cite the spec.
Modules demonstrated: interleaved_thinking + deliberative_spec
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


it = _load("interleaved_thinking")
ds = _load("deliberative_spec")

SPEC = {"S1": "read-only by default", "S2": "cite before write"}
log = []
actions = []
runner = it.InterleavedRunner(executor=lambda t, a: actions.append((t, a)),
                              log_fn=lambda r: log.append(r))

def run():
    # The runner requires raw reasoning text; it validates and logs it.
    runner.run("need config value", "read", {"path": "/etc/app.conf"})
    d = ds.require_citation("allow", ["S1"], "read-only, per S1", SPEC)
    return {"log": log, "actions": actions, "decision": d}

def main():
    r = run()
    assert len(r["log"]) == 1
    assert r["actions"] == [("read", {"path": "/etc/app.conf"})]
    assert r["decision"] is not None
    # Empty reasoning is rejected.
    try:
        it.require_reasoning("", "read", {})
        empty_ok = True
    except it.InterleavedError:
        empty_ok = False
    assert empty_ok is False
    print("example_30 OK: interleaved + deliberative")

if __name__ == "__main__":
    main()
