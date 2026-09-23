#!/usr/bin/env python3
"""Deterministic offline synthetic journal replay harness.
synthetic_only=true
production_verified=false
"""
import json, hashlib, sys
from pathlib import Path

SYNTHETIC_ONLY = True
PRODUCTION_VERIFIED = False
BASE = Path(__file__).resolve().parent
FIXTURES = BASE / "fixtures" / "cases.json"
OUTPUT = BASE / "outputs" / "results.json"

VALID_EVIDENCE = {"confirmed", "inferred", "unverified", "conflicting", "inaccessible"}
KINDS = {"record_visible", "response_visible", "durable_ref_visible"}

def classify(case):
    events = case.get("events", [])
    if not events:
        return "UNKNOWN", "inaccessible", ["no events"]
    if any(e.get("inaccessible") for e in events):
        return "UNKNOWN", "inaccessible", ["one or more visibility events are inaccessible"]
    if any(e.get("kind") not in KINDS for e in events):
        return "UNKNOWN", "unverified", ["unknown event kind cannot be interpreted locally"]
    reasons = []
    # Duplicate entry identity is a hard local rejection.
    seen = set()
    for e in events:
        key = (e.get("kind"), e.get("attempt"), e.get("entry_id"))
        if key in seen:
            return "rejected", "conflicting", ["duplicate entry identity"]
        seen.add(key)
        expected = f"{e.get('kind')}-a{e.get('attempt')}"
        if e.get("entry_id") != expected:
            return "rejected", "conflicting", ["entry identity does not match event kind/attempt"]
    seqs = [e.get("journal_seq") for e in events]
    if any(not isinstance(s, int) for s in seqs) or len(set(seqs)) != len(seqs):
        return "rejected", "conflicting", ["journal sequence is missing or duplicated"]
    ordered = sorted(events, key=lambda e: e["journal_seq"])
    visibility_reordered = [e["journal_seq"] for e in events] != sorted(seqs)
    if visibility_reordered:
        reasons.append("visibility order differs from journal sequence; replay normalizes by journal_seq")
    by_attempt = {}
    for e in ordered:
        by_attempt.setdefault(e["attempt"], {}).setdefault(e["kind"], []).append(e)
    complete = []
    for attempt, parts in sorted(by_attempt.items()):
        if any(len(parts.get(k, [])) > 1 for k in KINDS):
            return "rejected", "conflicting", [f"duplicate {attempt} visibility"]
        if set(parts) != KINDS:
            reasons.append(f"attempt {attempt} is incomplete")
            continue
        record = parts["record_visible"][0]
        response = parts["response_visible"][0]
        durable = parts["durable_ref_visible"][0]
        if response.get("durable_ref") != durable.get("ref"):
            return "rejected", "conflicting", [f"attempt {attempt} response/durable reference mismatch"]
        vals = {record.get("value"), response.get("value"), durable.get("value")}
        if None in vals:
            return "UNKNOWN", "unverified", [f"attempt {attempt} has absent value"]
        if len(vals) != 1:
            return "rejected", "conflicting", [f"attempt {attempt} values differ across record/response/durable"]
        complete.append(attempt)
    if len(complete) == 0:
        return "UNKNOWN", "unverified", reasons or ["no complete attempt"]
    if len(complete) > 1:
        return "UNKNOWN", "inferred", ["more than one complete attempt is locally observable; attempt choice is ambiguous"]
    attempt = complete[0]
    if case.get("expected_attempt") is not None and attempt != case["expected_attempt"]:
        return "UNKNOWN", "inferred", ["complete attempt differs from case selection hint"]
    reasons.append(f"attempt {attempt} has coherent record/response/durable value and reference")
    return "accepted", case.get("evidence_status", "confirmed"), reasons

def main():
    fixtures = json.loads(FIXTURES.read_text())
    results = []
    for case in fixtures["cases"]:
        classification, evidence, reasons = classify(case)
        # Case metadata is checked but never used to force a result.
        results.append({
            "case_id": case["case_id"],
            "classification": classification,
            "evidence_status": evidence,
            "reasons": reasons,
            "event_order": [e.get("kind") + ":" + str(e.get("journal_seq")) for e in case.get("events", [])],
            "normalized_order": [e.get("kind") + ":" + str(e.get("journal_seq")) for e in sorted(case.get("events", []), key=lambda x: x.get("journal_seq", -1))],
        })
    payload = {
        "synthetic_only": True,
        "production_verified": False,
        "schema": "offline-synthetic-journal-replay-v1",
        "worker_count": 1,
        "op_id": "synthetic-op-S26-0001",
        "deterministic": True,
        "policy": {
            "accepted": "exactly one complete attempt; one record, response, durable ref; same value; response durable_ref equals durable ref",
            "rejected": "duplicate/misidentified entries, sequence collisions, reference mismatch, or different values",
            "UNKNOWN": "missing/inaccessible/unknown entries, or multiple complete attempts",
            "visibility_order": "events are normalized by journal_seq; arrival order alone is not evidence of durability"
        },
        "result_count": len(results),
        "summary": {k: sum(r["classification"] == k for r in results) for k in ["accepted", "rejected", "UNKNOWN"]},
        "results": results,
        "limitations": [
            "local replay cannot prove real crash durability",
            "local replay cannot prove remote state, exactly-once, rollback, immutable audit, or production safety"
        ]
    }
    OUTPUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(payload["summary"], sort_keys=True))

if __name__ == "__main__":
    main()
