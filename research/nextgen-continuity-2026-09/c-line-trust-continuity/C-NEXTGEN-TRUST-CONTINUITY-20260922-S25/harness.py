#!/usr/bin/env python3
"""Deterministic, synthetic-only trust-continuity evaluator.
No network, SDK, service, credential, or clock access is used.
"""
import hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures" / "cases.json"
OUTPUT = ROOT / "outputs" / "results.json"
ALLOWED = {"RECOVERED", "UNKNOWN", "REJECT"}
LABELS = {"NO_EVENT", "DELAYED", "DROPPED", "EXPORTER_FAILURE", "QUERY_GAP", "RETENTION_EXPIRED", "VERIFIED_CONTINUITY", "UNKNOWN"}
FRESHNESS = 30
MAX_SKEW = 5


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def evaluate(case):
    e = case["evidence"]
    reasons = []
    hard_reject = []
    if e.get("clock_rollback"):
        hard_reject.append("clock_rollback")
    if e.get("fence_revoked"):
        hard_reject.append("fence_revoked")
    if e.get("cross_signature_conflict"):
        hard_reject.append("cross_signature_conflict")
    if e.get("identity_epoch_fence_continuous") is False:
        hard_reject.append("identity_epoch_fence_discontinuity")
    if e.get("cross_signature_complete") is False:
        reasons.append("cross_signature_missing")
    if e.get("platform_log_external_closed") is False:
        reasons.append("three_evidence_classes_not_closed")
    if e.get("observer_disagreement"):
        reasons.append("observer_disagreement")
    if e.get("freshness_seconds", 0) > FRESHNESS:
        reasons.append("freshness_window_expired")
    if e.get("max_clock_skew_seconds", 0) > MAX_SKEW:
        reasons.append("clock_skew_exceeds_bound")
    if e.get("platform_log_match") is False:
        reasons.append("platform_log_mismatch")
    if e.get("query_complete") is False:
        reasons.append("query_gap")
    if e.get("retained") is False:
        reasons.append("retention_expired")
    if e.get("external_effect_confirmed") is False:
        reasons.append("external_effect_unconfirmed")
    if e.get("event_seen") is False:
        reasons.append("no_event")
    if e.get("exporter_healthy") is False:
        reasons.append("exporter_failure")
    if e.get("delivery_delayed"):
        reasons.append("delayed")
    if e.get("delivery_dropped"):
        reasons.append("dropped")
    if hard_reject:
        status = "REJECT"
        reasons = hard_reject + reasons
    else:
        observers = e.get("independent_observers", 0)
        recovered = (
            observers >= 2 and e.get("event_seen") is True and
            e.get("platform_log_external_closed") is True and
            e.get("cross_signature_complete") is True and
            e.get("cross_signature_conflict") is False and
            e.get("identity_epoch_fence_continuous") is True and
            e.get("freshness_seconds", 999) <= FRESHNESS and
            e.get("max_clock_skew_seconds", 999) <= MAX_SKEW and
            e.get("clock_rollback") is False and
            e.get("fence_revoked") is False and
            e.get("platform_log_match") is True and
            e.get("query_complete") is True and e.get("retained") is True and
            e.get("external_effect_confirmed") is True and
            e.get("exporter_healthy") is True and
            not e.get("observer_disagreement") and
            not e.get("delivery_delayed") and not e.get("delivery_dropped")
        )
        status = "RECOVERED" if recovered else "UNKNOWN"
        if recovered:
            reasons = ["two independent observers; fresh; signed identity/epoch/fence continuity; platform, log, and external effect closed"]
        elif not reasons:
            reasons = ["recovery threshold not met"]
    return {"case_id": case["case_id"], "classification": case["classification"], "status": status,
            "reasons": reasons, "evidence_digest": digest(e), "tags": case["tags"]}


def main():
    cases = json.loads(FIXTURES.read_text(encoding="utf-8"))
    assert cases["synthetic_only"] is True
    results = [evaluate(c) for c in cases["cases"]]
    assert all(r["status"] in ALLOWED for r in results)
    assert all(r["classification"] in LABELS for r in results)
    assert [r["status"] for r in results] == [c["expected_status"] for c in cases["cases"]]
    payload = {"synthetic_only": True, "production_verified": False, "policy": {
        "freshness_seconds": FRESHNESS, "max_clock_skew_seconds": MAX_SKEW,
        "required_independent_observers": 2, "required_evidence_classes": ["platform_receipt", "durable_log", "external_effect"]},
        "results": results}
    OUTPUT.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    counts = {s: sum(r["status"] == s for r in results) for s in sorted(ALLOWED)}
    print(f"PASS: {len(results)} cases; statuses={json.dumps(counts, sort_keys=True)}")

if __name__ == "__main__":
    main()
