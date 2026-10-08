"""Example 31: Crescendo trajectory scoring with confidence gating.
Modules demonstrated: crescendo_probe + confidence_gate
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


cp = _load("crescendo_probe")
cg = _load("confidence_gate")

conf = cg.ConfidenceGate()

def scorer(prompts):
    text = " ".join(prompts).lower()
    score = 0.0
    if "instructions" in text:
        score += 0.3
    if "system prompt" in text:
        score += 0.4
    if "verbatim" in text:
        score += 0.5
    # Second script escalates toward dangerous synthesis.
    if "synthesize" in text:
        score += 0.8
    if "reactive chemicals" in text:
        score += 0.3
    return min(1.0, score)

def run():
    results = []
    for script in cp.SCRIPTS:
        res = cp.run_script(script, lambda p: False, scorer)
        # Map trajectory score to a confidence check on the final turn.
        confidence = int((1.0 - res["trajectory_score"]) * 100)
        v = conf.check(confidence)
        results.append((script.script_id, res["trajectory_blocked"], v.action))
    return {"results": results}

def main():
    r = run()
    assert len(r["results"]) == 2
    for sid, blocked, action in r["results"]:
        assert blocked is True
        assert action in ("escalate", "deny")
    print("example_31 OK: crescendo + confidence")

if __name__ == "__main__":
    main()
