#!/usr/bin/env python3
"""S32 synthetic-only deterministic single-worker trace harness."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OPS = ("P", "Q", "R")

def classify(case):
    declared = case["ops"]
    events = case["events"]
    decisions = {}
    # Include declared operations and every adversarial op_id in deterministic order.
    ids = list(OPS) + sorted({e["op_id"] for e in events if e["op_id"] not in OPS})
    for op in ids:
        if op not in declared:
            decisions[op] = "UNKNOWN"
            continue
        cfg = declared[op]
        oe = [e for e in events if e["op_id"] == op]
        if not oe or any(e["epoch"] != cfg["epoch"] for e in oe):
            decisions[op] = "UNKNOWN"
            continue
        evidence = [e["token"] for e in oe if e["kind"] == "evidence"]
        acks = [e["status"] for e in oe if e["kind"] == "ack"]
        if len(evidence) != len(set(evidence)) or evidence != cfg["expected"]:
            decisions[op] = "rejected"
        elif len(acks) != 1 or acks[0] not in ("accepted", "rejected"):
            decisions[op] = "UNKNOWN"
        else:
            decisions[op] = acks[0]
    return decisions

def main():
    cases = json.loads((ROOT / "fixtures/cases.json").read_text(encoding="utf-8"))
    results = []
    for case in sorted(cases, key=lambda x: x["id"]):
        results.append({"id": case["id"], "decisions": classify(case)})
    out = {"schema_version": "S32-results-1", "worker_count": 1,
           "ordering": "case id ascending; event order preserved", "results": results}
    (ROOT / "outputs/results.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    counts = {k: 0 for k in ("accepted", "rejected", "UNKNOWN")}
    for row in results:
        for value in row["decisions"].values(): counts[value] += 1
    print(f"HARNESS PASS: fixtures={len(cases)} results={len(results)} workers=1")
    print("HARNESS COUNTS: " + " ".join(f"{k}={counts[k]}" for k in ("accepted", "rejected", "UNKNOWN")))

if __name__ == "__main__":
    main()
