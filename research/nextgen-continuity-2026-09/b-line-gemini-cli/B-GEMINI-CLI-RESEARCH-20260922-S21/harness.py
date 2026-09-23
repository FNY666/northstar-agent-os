#!/usr/bin/env python3
# synthetic_only=true
# production_verified=false
"""Deterministic offline journal/recovery protocol model for S21.
This is a model checker, not a Gemini CLI implementation or production test.
"""
import hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def digest(x):
    return hashlib.sha256(json.dumps(x, sort_keys=True).encode()).hexdigest()[:16]

def run_case(case):
    evs = case["events"]
    intents = {}
    responses = {}
    durable = {}
    reconciles = {}
    dedups = {}
    seen_restart = set()
    violations = []
    contradictions = []
    notes = []
    local_journal = set()
    unknown = set()
    retry_seen = set()

    def add(code, msg, severity="error"):
        (contradictions if severity == "contradiction" else violations).append({"code": code, "message": msg})

    for n, e in enumerate(evs):
        kind = e.get("type")
        op = e.get("op_id")
        att = e.get("attempt")
        key = (op, att)
        if kind == "dispatch_intent":
            h = e.get("intent_hash") or digest(e.get("intent", {}))
            old = intents.get(key)
            if old and old != h:
                add("INTENT_HASH_CONFLICT", f"event {n}: same operation/attempt has different intent hash", "contradiction")
            intents[key] = h
            notes.append(f"{key}: local dispatch intent recorded; no remote completion inferred")
        elif kind == "tool_response":
            if key not in intents:
                add("RESPONSE_WITHOUT_INTENT", f"event {n}: tool response has no matching dispatch intent", "contradiction")
                continue
            effect = e.get("remote_effect")
            if effect not in {"applied", "not_applied", "unknown"}:
                add("INVALID_EFFECT", f"event {n}: remote_effect must be applied/not_applied/unknown", "contradiction")
                continue
            old = responses.get(key)
            if old and old != {"response_id": e.get("response_id"), "remote_effect": effect}:
                add("RESPONSE_CONFLICT", f"event {n}: conflicting tool responses for {key}", "contradiction")
            responses[key] = {"response_id": e.get("response_id"), "remote_effect": effect}
            notes.append(f"{key}: response observed ({effect}); response is not durable proof of remote state")
        elif kind == "durable_result":
            if key not in intents:
                add("DURABLE_WITHOUT_INTENT", f"event {n}: durable result has no matching intent", "contradiction")
                continue
            ref = e.get("response_id")
            r = responses.get(key)
            if not r:
                add("DURABLE_WITHOUT_RESPONSE", f"event {n}: durable result has no matching tool response", "contradiction")
            elif ref != r.get("response_id"):
                add("DURABLE_RESPONSE_REF_CONFLICT", f"event {n}: durable result references {ref!r}, observed {r.get('response_id')!r}", "contradiction")
            if key in durable and durable[key] != e.get("result_hash"):
                add("DURABLE_RESULT_CONFLICT", f"event {n}: durable result changed for {key}", "contradiction")
            durable[key] = e.get("result_hash")
            local_journal.add(key)
            notes.append(f"{key}: local durable result committed; remote completion remains unproven")
        elif kind == "crash":
            if key not in intents:
                add("CRASH_WITHOUT_INTENT", f"event {n}: crash references unknown attempt", "contradiction")
            else:
                unknown.add(key)
                notes.append(f"{key}: crash makes in-flight completion unknown")
        elif kind == "restart":
            seen_restart.add(op)
            notes.append(f"{op}: process restart; only durable local records are recoverable")
        elif kind == "resume":
            if op not in seen_restart:
                add("RESUME_BEFORE_RESTART", f"event {n}: resume before restart for {op}", "contradiction")
            if key not in intents:
                add("RESUME_UNKNOWN_ATTEMPT", f"event {n}: resume has no journal intent for {key}", "contradiction")
            if key in intents and key not in local_journal:
                unknown.add(key)
                notes.append(f"{key}: resume found intent but no durable result => UNKNOWN")
        elif kind == "retry":
            new_key = (op, e.get("new_attempt"))
            retry_seen.add(new_key)
            if op is None or new_key[1] is None:
                add("INVALID_RETRY", f"event {n}: retry lacks op_id/new_attempt", "contradiction")
            prior = [k for k in intents if k[0] == op]
            if prior and any(k in unknown for k in prior) and not e.get("dedup_key"):
                add("RETRY_UNKNOWN_WITHOUT_DEDUP", f"event {n}: retry while prior attempt is UNKNOWN without dedup key")
            if new_key in intents:
                add("RETRY_ATTEMPT_REUSE", f"event {n}: retry reuses existing attempt {new_key}", "contradiction")
            notes.append(f"{new_key}: retry requested; dedup/reconcile gate must be checked")
        elif kind == "dedup":
            canonical = (op, e.get("canonical_attempt"))
            if canonical not in intents:
                add("DEDUP_CANONICAL_MISSING", f"event {n}: dedup points to missing canonical attempt {canonical}", "contradiction")
            if e.get("outcome") not in {"suppressed", "same_result", "not_duplicate", "unknown"}:
                add("INVALID_DEDUP_OUTCOME", f"event {n}: invalid dedup outcome", "contradiction")
            dedups[key] = e.get("outcome")
            notes.append(f"{key}: dedup outcome {e.get('outcome')}")
        elif kind == "manual_reconcile":
            status = e.get("remote_status")
            if status not in {"applied", "not_applied", "conflict", "unknown"}:
                add("INVALID_RECONCILE_STATUS", f"event {n}: invalid remote_status", "contradiction")
                continue
            old = reconciles.get(op)
            if old and old != status and "conflict" not in {old, status}:
                add("RECONCILE_CONFLICT", f"event {n}: manual reconcile changed {op} from {old} to {status}", "contradiction")
            reconciles[op] = status
            notes.append(f"{op}: explicit manual reconcile says remote={status}")
        else:
            add("UNKNOWN_EVENT", f"event {n}: unsupported event type {kind!r}", "contradiction")

    # Invariants are checked after replay so cross-event contradictions are visible.
    for key, r in responses.items():
        if r["remote_effect"] == "applied" and key not in durable:
            notes.append(f"{key}: applied response without durable result => local recovery UNKNOWN")
    for op, status in reconciles.items():
        if status == "applied":
            notes.append(f"{op}: remote applied is asserted only by explicit reconcile, never journal inference")
    for key in unknown:
        if key in durable:
            # Durable result after a crash is okay only as a later commit; it does not erase remote uncertainty.
            notes.append(f"{key}: durable result exists after UNKNOWN transition; remote uncertainty retained")

    passed = not violations and not contradictions
    result = "PASS" if passed else ("CONTRADICTION_REJECTED" if contradictions else "UNSAFE_REJECTED")
    return {"id": case["id"], "description": case["description"], "expected": case["expected"],
            "result": result, "pass": result == case["expected"], "events": len(evs),
            "violations": violations, "contradictions": contradictions, "unknown_keys": sorted([list(x) for x in unknown]),
            "local_durable_keys": sorted([list(x) for x in local_journal]), "notes": notes}

def main():
    fixtures = json.loads((ROOT / "fixtures" / "cases.json").read_text())
    results = [run_case(c) for c in fixtures["cases"]]
    stats = {"total": len(results), "pass": sum(r["pass"] for r in results),
             "failed": sum(not r["pass"] for r in results),
             "by_result": {}}
    for r in results: stats["by_result"][r["result"]] = stats["by_result"].get(r["result"], 0) + 1
    out = {"synthetic_only": True, "production_verified": False, "model": "S21-journal-recovery-v1",
           "stats": stats, "results": results,
           "residual_unknown": [r["id"] for r in results if r["unknown_keys"]],
           "limitations": ["No network, process, filesystem crash, Gemini CLI, or remote service was exercised.",
                           "A tool response and a local durable result do not prove remote side effects."]}
    (ROOT / "outputs" / "results.json").write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(stats, ensure_ascii=False, sort_keys=True))
    print("RESIDUAL_UNKNOWN=" + json.dumps(out["residual_unknown"], ensure_ascii=False))
    return 0 if stats["failed"] == 0 else 1
if __name__ == "__main__":
    raise SystemExit(main())
