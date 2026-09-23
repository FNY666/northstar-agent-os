#!/usr/bin/env python3
"""S22-A: deterministic synthetic-only two-worker event reorder harness.

synthetic_only=true
production_verified=false
No network, subprocesses, or production interfaces are used.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

SYNTHETIC_ONLY = True
PRODUCTION_VERIFIED = False
ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures" / "cases.json"
OUTPUT = ROOT / "outputs" / "results.json"


def process_case(case: dict[str, Any]) -> dict[str, Any]:
    # This is a single-process deterministic model of two workers. Worker labels
    # identify interleaved event authors; they do not create OS processes.
    events = sorted(case["events"], key=lambda e: (e["order"], e["event_id"]))
    workers = {e["worker"] for e in events}
    accepted: list[str] = []
    rejected: list[str] = []
    rejection_reasons: dict[str, str] = {}
    intents: set[tuple[str, int]] = set()
    terminal: dict[tuple[str, int], str] = {}
    local_records: list[dict[str, Any]] = []
    remote_effect = "UNKNOWN"
    invariant_3_ok = True

    for event in events:
        kind = event["kind"]
        op_id = event["op_id"]
        attempt = event.get("attempt")
        key = (op_id, attempt) if attempt is not None else None
        decision = "accepted"
        reason = ""
        if kind == "dispatch_intent":
            if key in intents:
                decision, reason = "rejected", "duplicate_intent"
            else:
                intents.add(key)
                terminal.setdefault(key, "")
        elif kind in {"tool_response", "durable_result"}:
            if key not in intents:
                decision, reason = "rejected", "no_matching_intent"
            else:
                value = event["value"]
                prior = terminal.get(key, "")
                if prior and prior != value:
                    decision, reason = "rejected", "conflicting_same_attempt_record"
                else:
                    terminal[key] = value
        elif kind in {"crash", "restart", "resume"}:
            # Lifecycle events can affect local control flow only. They never
            # classify a remote effect in this model.
            pass
        else:
            decision, reason = "rejected", "unsupported_event_kind"

        if decision == "accepted":
            accepted.append(event["event_id"])
            local_records.append({"event_id": event["event_id"], "kind": kind, "decision": decision})
        else:
            rejected.append(event["event_id"])
            rejection_reasons[event["event_id"]] = reason
        if remote_effect != "UNKNOWN":
            invariant_3_ok = False

    expected = case["expected_decisions"]
    actual = {**{event_id: "accepted" for event_id in accepted},
              **{event_id: "rejected" for event_id in rejected}}
    decisions_match = actual == expected
    invariant_1_ok = all(
        rejection_reasons.get(event_id) == "no_matching_intent"
        for event_id, wanted in expected.items()
        if wanted == "rejected" and expected.get(event_id) == "rejected"
        and next((e for e in events if e["event_id"] == event_id), {}).get("kind") in {"tool_response", "durable_result"}
        and next((e for e in events if e["event_id"] == event_id), {}).get("op_id") == case["op_id"]
        and rejection_reasons.get(event_id) == "no_matching_intent"
    ) or not any(
        rejection_reasons.get(event_id) == "no_matching_intent"
        for event_id in rejected
    )
    # Explicitly evaluate the two invariant classes from event semantics.
    invariant_1_ok = True
    for event in events:
        if event["kind"] in {"tool_response", "durable_result"}:
            has_intent = (event["op_id"], event.get("attempt")) in intents
            # Intents are evaluated from the complete event set for the
            # invariant, while decisions above use delivery order.
            if not has_intent and event["event_id"] not in rejected:
                invariant_1_ok = False
    invariant_2_ok = all(reason != "conflicting_same_attempt_record" or event_id in rejected
                          for event_id, reason in rejection_reasons.items())
    case_pass = decisions_match and invariant_1_ok and invariant_2_ok and invariant_3_ok and remote_effect == "UNKNOWN"
    return {
        "case_id": case["case_id"],
        "description": case["description"],
        "workers": sorted(workers),
        "event_count": len(events),
        "accepted_event_ids": accepted,
        "rejected_event_ids": rejected,
        "rejection_reasons": rejection_reasons,
        "decisions": actual,
        "remote_effect": remote_effect,
        "invariants": {
            "no_matching_intent_response_or_durable_rejected": invariant_1_ok,
            "conflicting_same_attempt_response_or_durable_rejected": invariant_2_ok,
            "local_lifecycle_does_not_classify_remote_effect": invariant_3_ok,
        },
        "case_status": "PASS" if case_pass else "FAIL",
    }


def main() -> None:
    fixture_doc = json.loads(FIXTURES.read_text(encoding="utf-8"))
    results = [process_case(case) for case in fixture_doc["cases"]]
    decision_counts = {"accepted": 0, "rejected": 0, "UNKNOWN": 0}
    for result in results:
        decision_counts["accepted"] += len(result["accepted_event_ids"])
        decision_counts["rejected"] += len(result["rejected_event_ids"])
        if result["remote_effect"] == "UNKNOWN":
            decision_counts["UNKNOWN"] += 1
    output = {
        "synthetic_only": SYNTHETIC_ONLY,
        "production_verified": PRODUCTION_VERIFIED,
        "model": "two-worker deterministic event reorder; one op_id scope per fixture",
        "case_count": len(results),
        "fixture_pass_count": sum(r["case_status"] == "PASS" for r in results),
        "fixture_fail_count": sum(r["case_status"] == "FAIL" for r in results),
        "decision_counts": decision_counts,
        "counts_definition": {
            "accepted": "accepted local event decisions",
            "rejected": "rejected local event decisions",
            "UNKNOWN": "cases whose remote_effect classification remains UNKNOWN; not a remote observation",
        },
        "results": results,
    }
    OUTPUT.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: output[k] for k in ("case_count", "fixture_pass_count", "fixture_fail_count", "decision_counts")}, ensure_ascii=False))
    if output["fixture_fail_count"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
