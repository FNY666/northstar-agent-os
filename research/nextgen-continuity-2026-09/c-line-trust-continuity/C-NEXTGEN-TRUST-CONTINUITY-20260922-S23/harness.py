#!/usr/bin/env python3
"""Deterministic, offline-only trust-continuity synthetic harness."""
import json, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIX = ROOT / "fixtures" / "cases.json"
OUT = ROOT / "outputs" / "results.json"
VALID = {"RECOVERED", "UNKNOWN", "REJECT"}


def digest(obj):
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def evaluate(c):
    ev = c["evidence"]
    reasons = []
    # Fail closed: reject explicit writer fencing/token violations first.
    if ev.get("token_status") in {"STALE", "MISSING", "CONFLICT", "EPOCH_MISMATCH"}:
        state = "REJECT"
        reasons.append("audit_reject:" + ev["token_status"].lower())
    elif ev.get("audit_rejection_reason"):
        state = "REJECT"
        reasons.append("audit_reject:" + ev["audit_rejection_reason"])
    elif ev.get("contradiction"):
        state = "UNKNOWN"
        reasons.append("verifiable_contradiction")
    elif (ev.get("platform_receipt") == "ACCEPTED" and
          ev.get("log_presence") == "PRESENT" and
          ev.get("external_effect") == "CONFIRMED" and
          ev.get("continuity") == "VERIFIED_CONTINUITY" and
          ev.get("classification") == "VERIFIED_CONTINUITY"):
        state = "RECOVERED"
        reasons.append("all_independent_evidence_agrees")
    else:
        state = "UNKNOWN"
        reasons.append("insufficient_independent_evidence")
    return {
        "case_id": c["case_id"], "state": state,
        "classification": ev["classification"],
        "epoch": ev["epoch"], "fence_token": ev.get("fence_token"),
        "audit_rejection_reason": ev.get("audit_rejection_reason"),
        "evidence": {"platform_receipt": ev.get("platform_receipt"),
                     "log_presence": ev.get("log_presence"),
                     "external_effect": ev.get("external_effect"),
                     "continuity": ev.get("continuity")},
        "reasons": reasons,
        "contradiction": bool(ev.get("contradiction")),
    }


def main():
    cases = json.loads(FIX.read_text())
    results = [evaluate(c) for c in cases]
    payload = {
        "schema": "trust-continuity-s23-results-v1",
        "synthetic_only": True, "production_verified": False,
        "deterministic": True, "case_count": len(results),
        "results": results,
        "state_counts": {s: sum(r["state"] == s for r in results) for s in sorted(VALID)},
        "result_digest": digest(results),
    }
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    print("HARNESS_PASS cases=%d digest=%s" % (len(results), payload["result_digest"]))

if __name__ == "__main__":
    main()
