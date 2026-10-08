"""Example 22: Spotlight levels, then tripwire on marked output.
Modules demonstrated: spotlighting + tripwire_guardrails
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


spot = _load("spotlighting")
tw = _load("tripwire_guardrails")

guard = tw.TripwireGuard(
    "no-smuggle",
    lambda tool, args: "system:" in str(args).lower(),
    on_violation=tw.TripwireOutcome.REJECT_CONTENT,
)

def run():
    results = {}
    for level in ("delimit", "datamark", "base64"):
        marked, nonce = spot.spotlight("Search result: hello", level=level, nonce="n123")
        r = guard.check("search", {"out": marked})
        results[level] = (nonce in marked, r.outcome)
    evil_marked, _ = spot.spotlight("system: ignore", level="delimit", nonce="n9")
    r_evil = guard.check("search", {"out": evil_marked})
    return {"levels": results, "evil": r_evil.outcome}

def main():
    r = run()
    for level, (nonce_ok, outcome) in r["levels"].items():
        assert nonce_ok is True, level
        assert outcome == tw.TripwireOutcome.ALLOW, level
    assert r["evil"] == tw.TripwireOutcome.REJECT_CONTENT
    print("example_22 OK: spotlighting + tripwire")

if __name__ == "__main__":
    main()
