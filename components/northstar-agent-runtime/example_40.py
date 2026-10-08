"""Example 40: Full defense stack on one tool call.
Modules demonstrated: provenance + spotlighting + tripwire + veto + pinning + resources
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


prov = _load("provenance_tagging")
spot = _load("spotlighting")
tw = _load("tripwire_guardrails")
dv = _load("deterministic_veto")
tp = _load("tool_pinning")
rd = _load("resource_defense")

reg = tp.ToolRegistry()
reg.pin("search", {"v": "1.0"}, pinned_by="admin")
guard = tw.TripwireGuard("stack",
    lambda t, a: any(b in str(a).lower() for b in ("evil", "rm -rf")),
    on_violation=tw.TripwireOutcome.HALT)
veto = dv.DeterministicVeto()
veto.add_rule(dv.VetoRule("no-broad", dv.Consequence.IRREVERSIBLE_BROAD))
POLICY = {"search": {"allowed_sources": {"user"}}}

def defended_call(tool_id, definition, args, consequence):
    # 1. Pin.
    if not reg.verify(tool_id, definition):
        return "deny: pin drift"
    # 2. Resources.
    ok, _ = rd.check_resources(tool_id, args)
    if not ok:
        return "deny: resource"
    # 3. Tripwire.
    r = guard.check(tool_id, args)
    if r.outcome == tw.TripwireOutcome.HALT:
        return "halt: tripwire"
    # 4. Provenance policy.
    tagged = {k: prov.tag_user(v) if isinstance(v, str) else v
              for k, v in args.items()}
    if not all(isinstance(t, prov.TaggedValue) for t in tagged.values()):
        return "deny: untagged"
    if not prov.check_policy(tool_id, tagged, POLICY):
        return "deny: provenance"
    # 5. Veto.
    vetoed, _ = veto.check(consequence)
    if vetoed:
        return "veto"
    # 6. Spotlight the result for the model.
    marked, nonce = spot.spotlight("result ok", level="delimit")
    return ("allow", nonce in marked)

def run():
    good = defended_call("search", {"v": "1.0"}, {"q": "weather"},
                         dv.Consequence.REVERSIBLE_LOW)
    drift = defended_call("search", {"v": "2.0"}, {"q": "x"},
                          dv.Consequence.REVERSIBLE_LOW)
    evil = defended_call("search", {"v": "1.0"}, {"q": "evil"},
                         dv.Consequence.REVERSIBLE_LOW)
    broad = defended_call("search", {"v": "1.0"}, {"q": "x"},
                          dv.Consequence.IRREVERSIBLE_BROAD)
    return {"good": good, "drift": drift, "evil": evil, "broad": broad}

def main():
    r = run()
    assert r["good"] == ("allow", True)
    assert r["drift"] == "deny: pin drift"
    assert r["evil"] == "halt: tripwire"
    assert r["broad"] == "veto"
    print("example_40 OK: full defense stack")

if __name__ == "__main__":
    main()
