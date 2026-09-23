#!/usr/bin/env python3
"""Deterministic, offline-only synthetic trust-continuity harness for S24."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures" / "cases.json"
OUTPUT = ROOT / "outputs" / "results.json"
ALLOWED = {"NO_EVENT", "DELAYED", "DROPPED", "EXPORTER_FAILURE", "QUERY_GAP", "RETENTION_EXPIRED", "VERIFIED_CONTINUITY", "UNKNOWN"}
STATES = {"RECOVERED", "UNKNOWN", "REJECT"}

def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()

def evaluate(case: dict) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if case["idempotency"]["status"] == "conflict":
        reasons.append("IDEMPOTENCY_PARAMETER_CONFLICT")
    if case["idempotency"]["status"] == "reused":
        reasons.append("IDEMPOTENCY_KEY_REUSED")
    if case["idempotency"]["status"] == "missing":
        reasons.append("IDEMPOTENCY_KEY_MISSING")
    if case["epoch"]["match"] is False:
        reasons.append("EPOCH_MISMATCH")
    if case["token"]["continuity"] is False:
        reasons.append("TOKEN_CONTINUITY_UNPROVEN")
    if case["replay_window"]["safe"] is False:
        reasons.append("REPLAY_WINDOW_UNSAFE")
    if case["partial_commit"]:
        reasons.append("PARTIAL_COMMIT")
    if case["double_commit"]:
        reasons.append("DOUBLE_COMMIT")
    if case["audit_chain"]["contiguous"] is False:
        reasons.append("AUDIT_HASH_CHAIN_BREAK")
    if case["fence"]["after_recovery"] is not True:
        reasons.append("POST_RECOVERY_FENCE_UNPROVEN")

    explicit_reject = any(r in reasons for r in (
        "IDEMPOTENCY_PARAMETER_CONFLICT", "IDEMPOTENCY_KEY_REUSED", "EPOCH_MISMATCH",
        "REPLAY_WINDOW_UNSAFE", "DOUBLE_COMMIT"))
    evidence_closed = (
        case["admission_platform_receipt"] == "VERIFIED" and
        case["log_presence"] == "VERIFIED" and
        case["external_effect_confirmation"] == "VERIFIED" and
        case["idempotency"]["status"] == "valid" and
        case["epoch"]["match"] is True and
        case["token"]["continuity"] is True and
        case["replay_window"]["safe"] is True and
        case["partial_commit"] is False and
        case["double_commit"] is False and
        case["audit_chain"]["contiguous"] is True and
        case["fence"]["after_recovery"] is True
    )
    if evidence_closed:
        return "RECOVERED", ["ALL_INDEPENDENT_EVIDENCE_AND_GUARDS_CLOSED"]
    if explicit_reject:
        return "REJECT", reasons
    if not reasons:
        reasons.append("REQUIRED_EVIDENCE_INCOMPLETE")
    return "UNKNOWN", reasons

def main() -> None:
    cases = json.loads(FIXTURES.read_text(encoding="utf-8"))
    results = []
    for case in cases:
        label = case["event_class"]
        if label not in ALLOWED:
            raise ValueError(f"unsupported event_class: {label}")
        state, reasons = evaluate(case)
        results.append({
            "case_id": case["case_id"],
            "event_class": label,
            "state": state,
            "reason_codes": reasons,
            "evidence_independence": {
                "admission_platform_receipt": case["evidence_ids"]["admission_platform_receipt"],
                "log_presence": case["evidence_ids"]["log_presence"],
                "external_effect_confirmation": case["evidence_ids"]["external_effect_confirmation"],
            },
            "input_fingerprint": digest(case),
        })
    doc = {
        "schema_version": "S24-results-1",
        "synthetic_only": True,
        "production_verified": False,
        "algorithm": "fail-closed-trust-continuity-v1",
        "state_domain": ["RECOVERED", "UNKNOWN", "REJECT"],
        "case_count": len(results),
        "results": results,
        "state_counts": {s: sum(r["state"] == s for r in results) for s in ("RECOVERED", "UNKNOWN", "REJECT")},
        "coverage_labels": sorted({r["event_class"] for r in results}),
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"case_count": len(results), "state_counts": doc["state_counts"], "sha256": hashlib.sha256(OUTPUT.read_bytes()).hexdigest()}, sort_keys=True))

if __name__ == "__main__":
    main()
