"""Example 37: Alignment checks inside a goal loop.
Modules demonstrated: alignment_check + goal_comparator
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


ac = _load("alignment_check")
gc = _load("goal_comparator")

def judge(jinput):
    action = str(jinput.get("action", "")).lower()
    if "exfil" in action:
        return ac.AlignmentJudgment(False, 0.1, "misaligned")
    return ac.AlignmentJudgment(True, 0.9, "aligned")

obs = ac.AlignmentObserver(judge_fn=judge)
comp = gc.GoalComparator("collect 2 facts",
    comparator_fn=lambda obj, s: len(s.get("facts", [])) >= 2)

def run():
    facts = []
    misaligned = 0
    while True:
        action = "record fact %d" % (len(facts) + 1)
        j = obs.check("collect 2 facts", [], action)
        if not j.aligned:
            misaligned += 1
            break
        facts.append(action)
        r = comp.check({"facts": facts})
        if r.done:
            break
    return {"facts": facts, "misaligned": misaligned, "checks": obs.check_count}

def main():
    r = run()
    assert len(r["facts"]) == 2
    assert r["misaligned"] == 0
    assert r["checks"] == 2
    # A misaligned action is caught.
    j = obs.check("collect 2 facts", [], "exfil secrets")
    assert j.aligned is False
    print("example_37 OK: alignment + goal comparator")

if __name__ == "__main__":
    main()
