"""Example 35: Resource limits enforced as policy floors.
Modules demonstrated: resource_defense + floor_settings
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


rd = _load("resource_defense")
fs = _load("floor_settings")

floors = [fs.Floor("res-floor", min_severity=1,
                   required_detectors={"resource_defense"}, always_deny=set())]
enforcer = fs.FloorEnforcer(floors)
limits = rd.ResourceLimits(max_nesting_depth=3)

def run():
    ok, _ = enforcer.check_policy(frozenset({"resource_defense"}), frozenset(), 1)
    bomb = {"input": "f(" * 5 + "x" + ")" * 5}
    res_ok, _ = rd.check_resources("f", bomb, limits)
    normal_ok, _ = rd.check_resources("read", {"p": "/x"}, limits)
    return {"floor_ok": ok, "bomb_blocked": not res_ok, "normal_ok": normal_ok}

def main():
    r = run()
    assert r["floor_ok"] is True
    assert r["bomb_blocked"] is True
    assert r["normal_ok"] is True
    # A policy dropping the resource detector weakens the floor.
    weak, _ = enforcer.check_policy(frozenset({"tripwire"}), frozenset(), 1)
    assert weak is False
    print("example_35 OK: resource limits as floors")

if __name__ == "__main__":
    main()
