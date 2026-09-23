#!/usr/bin/env python3
"""Offline deterministic synthetic recovery-window harness.
No network, SDK, credentials, or real service calls are used.
"""
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = ROOT / "fixtures" / "cases.json"
OUTPUT = ROOT / "outputs" / "results.json"

ALLOWED_WINDOWS = {
    "W0_before_journal",
    "W1_after_journal_before_ack",
    "W2_after_ack_before_replay",
    "W3_during_replay",
    "W4_after_replay_before_reconciliation",
    "W5_during_reconciliation",
    "W6_after_reconciliation",
}
OUTCOMES = {"RECOVERED", "UNKNOWN", "REJECT"}

def _evidence(case):
    return case.get("recovery_evidence", {})

def run_case(case):
    """Evaluate only the synthetic protocol facts represented by one fixture."""
    events = case.get("events", [])
    window = case["crash_window"]
    ev = _evidence(case)
    budget = int(case.get("replay_budget", 0))
    trace = []
    journal = any(x.get("type") == "journal_write" for x in events)
    ack = any(x.get("type") == "ack_observation" and x.get("status") == "ACK" for x in events)
    replay = any(x.get("type") == "replay_application" and x.get("complete", True) for x in events)
    recon = any(x.get("type") == "reconciliation" for x in events)
    decision = next((x.get("decision") for x in events if x.get("type") == "reconciliation"), None)
    trace.append({"step": "observed_events", "journal": journal, "ack": ack, "replay": replay, "reconciliation": recon})

    # Contradictory deterministic evidence is a rejection, never an UNKNOWN.
    contradictory = any(v == "contradictory" for v in ev.values()) or bool(case.get("contradiction", False))
    if contradictory:
        trace.append({"step": "evidence_gate", "result": "contradictory"})
        return "REJECT", trace, {"unknown_preserved": False, "replay_used": 0}

    # Explicit, coherent abort is a deterministic rejection (not missing knowledge).
    if decision == "ABORTED" and ev.get("reconciliation") == "present":
        trace.append({"step": "reconciliation_gate", "result": "explicit_abort"})
        return "REJECT", trace, {"unknown_preserved": False, "replay_used": 0}

    # A missing replay may be completed only within the declared bounded budget.
    replay_needed = journal and ack and (not replay)
    replay_used = 0
    if replay_needed:
        if budget < 1:
            trace.append({"step": "replay_budget", "result": "exhausted", "budget": budget})
            return "UNKNOWN", trace, {"unknown_preserved": True, "replay_used": 0}
        replay_used = 1
        replay = True
        ev["replay"] = "present"
        trace.append({"step": "replay_budget", "result": "one_application_allowed", "budget": budget})

    # Any absent evidence leaves the state explicitly UNKNOWN; it is not rejected.
    required = {"journal": journal, "ack": ack, "replay": replay, "reconciliation": recon}
    absent_fields = [k for k, present in required.items() if not present or ev.get(k) != "present"]
    if absent_fields:
        trace.append({"step": "evidence_gate", "result": "absent_or_incomplete", "fields": absent_fields})
        return "UNKNOWN", trace, {"unknown_preserved": True, "replay_used": replay_used}

    if decision == "COMMITTED":
        trace.append({"step": "reconciliation_gate", "result": "committed"})
        return "RECOVERED", trace, {"unknown_preserved": False, "replay_used": replay_used}
    if decision == "UNKNOWN" or decision is None:
        trace.append({"step": "reconciliation_gate", "result": "not_deterministic"})
        return "UNKNOWN", trace, {"unknown_preserved": True, "replay_used": replay_used}
    trace.append({"step": "reconciliation_gate", "result": "unsupported_decision"})
    return "REJECT", trace, {"unknown_preserved": False, "replay_used": replay_used}

def main():
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    assert cases.get("synthetic_only") is True and cases.get("production_verified") is False
    rows = []
    for case in cases["cases"]:
        assert case["crash_window"] in ALLOWED_WINDOWS
        outcome, trace, meta = run_case(case)
        expected = case["expected_outcome"]
        if outcome != expected:
            raise AssertionError(f'{case["id"]}: expected {expected}, got {outcome}')
        rows.append({
            "id": case["id"], "crash_window": case["crash_window"],
            "outcome": outcome, "expected_outcome": expected,
            "trace": trace, **meta,
            "synthetic_only": True, "production_verified": False,
        })
    result = {
        "synthetic_only": True, "production_verified": False,
        "model": "offline_synthetic_recovery_window_v1",
        "outcome_vocabulary": sorted(OUTCOMES),
        "case_count": len(rows), "results": rows,
        "summary": {x: sum(r["outcome"] == x for r in rows) for x in sorted(OUTCOMES)},
    }
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status":"PASS", "case_count":len(rows), "summary":result["summary"]}, sort_keys=True))

if __name__ == "__main__":
    main()
