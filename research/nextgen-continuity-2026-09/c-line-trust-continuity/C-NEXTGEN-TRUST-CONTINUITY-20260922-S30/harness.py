#!/usr/bin/env python3
"""Deterministic offline evaluator for cross-partition fence/replay evidence."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures" / "cases.json"
OUTPUT = ROOT / "outputs" / "results.json"

STATE = {"RECOVERED", "UNKNOWN", "REJECT"}
SWEEP_FIELDS = [
    "cursor_jump", "overlap_page", "retention_complete", "fence_merge",
    "out_of_order", "duplicate", "missing_page", "fence_continuous",
]

def classify(c):
    # Explicit, fail-closed precedence: irreconcilable evidence rejects;
    # incomplete/non-closed evidence remains unknown; only closure recovers.
    if c.get("payload_conflict", False) or c.get("fence_fork", False):
        state = "REJECT"
    elif (
        c.get("cursor_jump", False)
        or c.get("missing_page", False)
        or c.get("query_gap", False)
        or c.get("replay_truncated", False)
        or not c.get("retention_complete", False)
        or not c.get("fence_merge", False)
        or not c.get("fence_continuous", False)
    ):
        state = "UNKNOWN"
    else:
        state = "RECOVERED"
    return state

def check_case(c):
    state = classify(c)
    expected = c["expected_state"]
    if state != expected:
        raise AssertionError(f"{c['id']}: got {state}, expected {expected}")
    return {"id": c["id"], "state": state, "category": c["category"]}

def property_sweep():
    # Exhaust all 2^8 combinations; overlap/out-of-order/duplicate are
    # intentionally benign when all closure gates are present.
    rows = []
    violations = []
    for n in range(1 << len(SWEEP_FIELDS)):
        c = {"retention_complete": True, "fence_merge": True,
             "fence_continuous": True, "payload_conflict": False,
             "query_gap": False, "replay_truncated": False}
        for i, field in enumerate(SWEEP_FIELDS):
            c[field] = bool(n & (1 << i))
        got = classify(c)
        should_unknown = (
            c["cursor_jump"] or c["missing_page"]
            or not c["retention_complete"]
            or not c["fence_merge"]
            or not c["fence_continuous"]
        )
        expected = "UNKNOWN" if should_unknown else "RECOVERED"
        if got != expected or got == "REJECT":
            violations.append({"bits": n, "got": got, "expected": expected})
        rows.append({"bits": n, "state": got})
    counts = {s: sum(r["state"] == s for r in rows) for s in sorted(STATE)}
    return {"fields": SWEEP_FIELDS, "combinations": len(rows),
            "counts": counts, "violations": violations}

def single_gate_minimizer():
    # Find the smallest gate sets that independently prevent recovery.
    base = {"retention_complete": True, "fence_merge": True,
            "fence_continuous": True, "payload_conflict": False}
    gates = ["cursor_jump", "missing_page", "query_gap", "replay_truncated",
             "retention_complete", "fence_merge", "fence_continuous",
             "payload_conflict", "fence_fork"]
    found = {}
    for gate in gates:
        c = dict(base)
        if gate in {"retention_complete", "fence_merge", "fence_continuous"}:
            c[gate] = False
        else:
            c[gate] = True
        found[gate] = {"state": classify(c), "active_gates": [gate]}
    # A single conflict gate must reject; each completeness gate must be unknown.
    assert found["payload_conflict"]["state"] == "REJECT"
    assert found["fence_fork"]["state"] == "REJECT"
    for g in ("cursor_jump", "missing_page", "query_gap", "replay_truncated",
              "retention_complete", "fence_merge", "fence_continuous"):
        assert found[g]["state"] == "UNKNOWN", g
    return {"method": "single-gate exhaustive minimizer", "results": found}

def main():
    data = json.loads(FIXTURES.read_text(encoding="utf-8"))
    results = {"schema_version": "S30-harness-1", "cases": [check_case(c) for c in data["cases"]],
               "property_sweep": property_sweep(), "minimizer": single_gate_minimizer()}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(results, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    counts = {s: sum(x["state"] == s for x in results["cases"]) for s in sorted(STATE)}
    print(json.dumps({"cases": len(results["cases"]), "state_counts": counts,
                      "sweep": results["property_sweep"]["combinations"],
                      "violations": len(results["property_sweep"]["violations"]),
                      "output": str(OUTPUT)}, sort_keys=True))

if __name__ == "__main__":
    main()
