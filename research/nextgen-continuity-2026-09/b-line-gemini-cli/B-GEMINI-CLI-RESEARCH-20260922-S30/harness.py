#!/usr/bin/env python3
"""Offline deterministic S30 acknowledgement-state harness."""
# synthetic_only=true; production_verified=false
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = json.loads((ROOT / "fixtures/cases.json").read_text())


def classify(events):
    verified_fact = None
    ack_states = []
    for event in events:
        if event["type"] == "fact" and event.get("verified") and event.get("outcome") in {"accepted", "rejected"}:
            verified_fact = event["outcome"]
        if event["type"] == "ack" and event.get("evidence_available") is True and event.get("outcome") in {"accepted", "rejected"}:
            ack_states.append(event["outcome"])
    # A verified fact is authoritative; late or duplicate acknowledgements cannot rewrite it.
    if verified_fact is not None:
        return verified_fact
    # Without a fact, contradictory evidenced acks are unresolved, not rejected.
    if len(set(ack_states)) > 1:
        return "UNKNOWN"
    # A single evidenced ack establishes the synthetic state; duplicate identical acks do not.
    if len(set(ack_states)) == 1 and ack_states:
        return ack_states[0]
    return "UNKNOWN"


def main():
    results = {
        "synthetic_only": True,
        "production_verified": False,
        "schema_version": "S30-1.0",
        "worker_id": CASES["worker_id"],
        "op_id": CASES["op_id"],
        "results": []
    }
    for case in CASES["cases"]:
        actual = classify(case["events"])
        results["results"].append({"id": case["id"], "label": case["label"], "expected": case["expected"], "actual": actual, "pass": actual == case["expected"]})
    out = ROOT / "outputs/results.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    bad = [r for r in results["results"] if not r["pass"]]
    print(f"HARNESS_PASS: {len(results['results'])} fixtures; accepted/rejected/UNKNOWN classification deterministic") if not bad else print(f"HARNESS_FAIL: {bad}")
    return 0 if not bad else 1

if __name__ == "__main__":
    raise SystemExit(main())
