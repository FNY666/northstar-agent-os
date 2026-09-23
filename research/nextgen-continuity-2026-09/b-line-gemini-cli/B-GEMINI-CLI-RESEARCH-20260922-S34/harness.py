#!/usr/bin/env python3
"""Offline deterministic evaluator for S34 synthetic fixtures."""
from __future__ import annotations
import hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DECLARED = {"P", "Q", "R"}
ALLOWED_EPOCHS = set(range(1, 5))
VERDICTS = {"accepted", "rejected", "UNKNOWN"}

def canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def sha(obj):
    return hashlib.sha256(canon(obj).encode()).hexdigest()

def evaluate(case):
    batches = case.get("batches", [])
    seen = set(); unique = []; dup = 0
    for b in batches:  # arrival order is retained; no sorting
        key = (b.get("batch_id"), b.get("epoch"))
        if key in seen:
            dup += 1; continue
        seen.add(key); unique.append(b)
    opv = {}; reasons = {}; blockers = {}
    for op in ("P", "Q", "R", "X"):
        if op not in DECLARED:
            opv[op] = "UNKNOWN"; reasons[op] = "undeclared operation X"; blockers[op] = ["operation_not_declared"]
            continue
        observations = []
        for b in unique:
            epoch = b.get("epoch")
            for e in b.get("events", []):
                if e.get("op") != op: continue
                if b.get("revoked") is True:
                    # Revocation makes only this batch's event unknown; it is
                    # removed from the aggregate so other batches remain valid.
                    continue
                if epoch not in ALLOWED_EPOCHS:
                    observations.append(("unknown", f"epoch {epoch!r} cannot be assigned", "epoch_unassignable")); continue
                if e.get("kind") == "missing":
                    observations.append(("unknown", "event is missing", "event_missing")); continue
                if e.get("kind") != "ack" or e.get("status") not in ("accepted", "rejected"):
                    observations.append(("unknown", "ack status cannot be verified by the rule", "unverifiable_ack")); continue
                observations.append((e["status"], f"epoch {epoch} ack is {e['status']}", None))
        if not observations:
            opv[op] = "UNKNOWN"; reasons[op] = "no op-local accessible evidence"; blockers[op] = ["no_local_evidence"]
        elif any(x[0] == "unknown" for x in observations):
            # Missing/invalid evidence does not contaminate other operations, but is
            # unresolved for this operation when mixed with its own evidence.
            opv[op] = "UNKNOWN"; reasons[op] = "; ".join(x[1] for x in observations); blockers[op] = sorted({x[2] for x in observations if x[2]})
        else:
            statuses = {x[0] for x in observations}
            if statuses == {"accepted"}:
                opv[op] = "accepted"; reasons[op] = "all op-local acks agree"; blockers[op] = []
            elif statuses == {"rejected"}:
                opv[op] = "rejected"; reasons[op] = "all op-local acks agree on rejected"; blockers[op] = []
            else:
                opv[op] = "rejected"; reasons[op] = "conflicting accepted/rejected acks; conflict rule rejects only this op"; blockers[op] = ["op_local_ack_conflict"]
    batch_event_verdicts = []
    for b in unique:
        for e in b.get("events", []):
            if e.get("op") not in ("P", "Q", "R", "X"): continue
            if b.get("revoked") is True:
                v, why = "UNKNOWN", "batch explicitly revoked"
            elif b.get("epoch") not in ALLOWED_EPOCHS:
                v, why = "UNKNOWN", "epoch cannot be assigned"
            elif e.get("kind") == "ack" and e.get("status") in ("accepted", "rejected"):
                v, why = e["status"], "ack status is locally verifiable"
            else:
                v, why = "UNKNOWN", "event is missing or unverifiable"
            batch_event_verdicts.append({"batch_id": b.get("batch_id"), "epoch": b.get("epoch"), "op": e.get("op"), "verdict": v, "reason": why})
    target = case["target_op"]
    primary = batches[0]["batch_id"] if batches else None
    result = {
        "fixture_id": case["id"],
        "arrival_order": [b.get("batch_id") for b in batches],
        "epoch_sequence": [b.get("epoch") for b in batches],
        "batch_id": primary,
        "batch_ids": [b.get("batch_id") for b in batches],
        "batch_event_verdicts": batch_event_verdicts,
        "target_op": target,
        "op_verdict": opv[target],
        "op_verdicts": opv,
        "reason": reasons[target],
        "blocking_conditions": blockers[target],
        "duplicate_batches_ignored": dup,
        "canonical_input_sha256": sha(case),
    }
    return result

def main():
    data = json.loads((ROOT / "fixtures" / "cases.json").read_text(encoding="utf-8"))
    cases = data["cases"]
    results = [evaluate(c) for c in cases]
    for c, r in zip(cases, results):
        expected = c["expected"]
        if r["op_verdict"] != expected[r["target_op"]] or r["op_verdicts"] != expected:
            raise SystemExit(f"FAIL {c['id']}: expected {expected}, got {r['op_verdicts']}")
        if r["op_verdict"] not in VERDICTS: raise SystemExit(f"FAIL {c['id']}: invalid verdict")
    out = {"synthetic_only": True, "production_verified": False, "fixture_count": len(results), "results": results}
    (ROOT / "outputs" / "results.json").write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    counts = {v: sum(r["op_verdict"] == v for r in results) for v in ("accepted", "rejected", "UNKNOWN")}
    print(f"PASS: harness deterministic evaluation; fixtures={len(results)}; verdicts={counts}")
    print(f"PASS: duplicate_batches_ignored={sum(r['duplicate_batches_ignored'] for r in results)}; arrival order preserved")
    print("PASS: synthetic_only=true; production_verified=false")

if __name__ == "__main__": main()
