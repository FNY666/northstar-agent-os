#!/usr/bin/env python3
"""Deterministic synthetic-only trust-continuity harness for S28."""
import hashlib, json, itertools
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIX = ROOT / "fixtures" / "cases.json"
OUT = ROOT / "outputs" / "results.json"
GATES = [
    "membership_epoch_closed", "quorum_recomputed", "quorum_satisfied",
    "identity_no_equivocation", "revocation_watermark_reached",
    "bounded_replay_complete", "crash_restart_closed", "evidence_consistent",
]

def receipt_conflict(receipts):
    # A source is equivocal if it signs incompatible claims in one continuity
    # scope, or contradicts another region/epoch receipt in the same conflict group.
    seen = {}
    for r in receipts:
        key = (r["observer"], r.get("scope", r.get("conflict_group", "default")))
        claim = (r["epoch"], r["region"], r["claim"])
        if key in seen and seen[key] != claim:
            return True
        seen[key] = claim
    return False

def evaluate(c):
    gates = {k: bool(c["gates"].get(k, False)) for k in GATES}
    derived_conflict = receipt_conflict(c.get("receipts", []))
    hard_conflict = bool(c.get("hard_conflict", False) or derived_conflict)
    unsafe = any(bool(c.get(k, False)) for k in (
        "membership_not_converged", "quorum_split", "late_old_member_evidence",
        "query_gap", "retention_expired", "identity_reuse_conflict"))
    if hard_conflict:
        status = "REJECT"
        reason = "hard_conflict_or_receipt_equivocation"
    elif all(gates.values()) and not unsafe:
        status = "RECOVERED"
        reason = "closed_membership_quorum_provenance_replay_and_effects"
    else:
        status = "UNKNOWN"
        failed = [k for k, v in gates.items() if not v]
        flags = [k for k in ("membership_not_converged", "quorum_split", "late_old_member_evidence", "query_gap", "retention_expired", "identity_reuse_conflict") if c.get(k)]
        reason = ";".join(failed + flags) or "insufficient_continuity_proof"
    return {"case_id": c["case_id"], "classification": c["classification"], "status": status, "reason": reason}

def property_sweep():
    # Exhaustive 2^8 gate combinations: recovery is permitted only at all-true.
    violations = []
    base = {"gates": {}, "receipts": []}
    for bits in itertools.product((False, True), repeat=len(GATES)):
        c = dict(base)
        c["gates"] = dict(zip(GATES, bits))
        c["case_id"] = "property"
        c["classification"] = "UNKNOWN"
        got = evaluate(c)["status"]
        expected = "RECOVERED" if all(bits) else "UNKNOWN"
        if got != expected:
            violations.append({"bits": bits, "got": got, "expected": expected})
    return {"combinations": 2 ** len(GATES), "violations": len(violations), "details": violations}

def minimizer():
    found = []
    for gate in GATES:
        c = {"case_id": "min", "classification": "UNKNOWN", "gates": {g: True for g in GATES}, "receipts": []}
        c["gates"][gate] = False
        got = evaluate(c)["status"]
        found.append({"blocked_gate": gate, "status": got, "minimal_faults": 1})
    return {"requested_gates": len(GATES), "found": len(found), "counterexamples": found}

def main():
    cases = json.loads(FIX.read_text(encoding="utf-8"))
    results = [evaluate(c) for c in cases]
    counts = {s: sum(x["status"] == s for x in results) for s in ("RECOVERED", "UNKNOWN", "REJECT")}
    labels = sorted({c["classification"] for c in cases})
    payload = {
        "schema_version": "S28.synthetic.results.v1",
        "synthetic_only": True,
        "production_verified": False,
        "cases": results,
        "summary": {"case_count": len(results), "status_counts": counts, "coverage_labels": labels},
        "property_sweep": property_sweep(),
        "minimizer": minimizer(),
    }
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload["summary"], sort_keys=True))
    print(json.dumps({"property_sweep": payload["property_sweep"], "minimizer": payload["minimizer"]}, sort_keys=True))

if __name__ == "__main__":
    main()
