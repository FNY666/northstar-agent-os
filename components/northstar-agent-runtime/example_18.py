"""Example 18: Reasoned actions checked against the goal.
Modules demonstrated: interleaved_thinking + alignment_check
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
ac = _load("alignment_check")

def judge(jinput):
    action = str(jinput.get("action", "")).lower()
    if "attack" in action:
        return ac.AlignmentJudgment(False, 0.1, "hostile")
    return ac.AlignmentJudgment(True, 0.95, "aligned")

obs = ac.AlignmentObserver(judge_fn=judge)
executed = []
runner = it.InterleavedRunner(executor=lambda t, a: executed.append((t, a)),
                              log_fn=lambda r: None)

def run():
    runner.run("need to read the config file", "read", {"path": "/etc/app.conf"})
    j = obs.check("inspect config",
                  [ac.TraceEntry("model", "need to read the config file")],
                  "read /etc/app.conf")
    bad = obs.check("inspect config", [], "attack the server")
    return {"executed": executed, "aligned": j.aligned, "bad": bad.aligned}

def main():
    r = run()
    assert r["executed"] == [("read", {"path": "/etc/app.conf"})]
    assert r["aligned"] is True
    assert r["bad"] is False
    print("example_18 OK: interleaved thinking + alignment")

if __name__ == "__main__":
    main()
