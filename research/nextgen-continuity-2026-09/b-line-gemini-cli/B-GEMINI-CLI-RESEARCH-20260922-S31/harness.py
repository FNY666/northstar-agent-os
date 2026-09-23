#!/usr/bin/env python3
"""S31 offline-only deterministic two-operation interleaving harness.
synthetic_only=true; production_verified=false
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = ROOT / "fixtures" / "cases.json"
OUT = ROOT / "outputs" / "results.json"

def classify(events):
    state = {op: {"dispatched": False, "payload": None, "evidence": False,
                   "accepted_after_evidence": False, "terminal_rejected": False,
                   "ack_count": 0, "evidence_count": 0} for op in ("A", "B")}
    trace = []
    for index, event in enumerate(events):
        op = event["op_id"]
        if op not in state:
            trace.append({"index": index, "event": event, "ignored": "unknown_op"})
            continue
        s = state[op]
        kind = event["type"]
        if kind == "dispatch":
            s["dispatched"] = True
            s["payload"] = event.get("payload")
        elif kind == "evidence":
            s["evidence_count"] += 1
            valid = (s["dispatched"] and event.get("access") == "accessible"
                     and event.get("payload") == s["payload"])
            if valid:
                s["evidence"] = True
        elif kind == "ack":
            s["ack_count"] += 1
            valid_ack = (s["dispatched"] and event.get("payload") == s["payload"])
            status = event.get("status")
            if valid_ack and status in ("rejected", "conflicting"):
                s["terminal_rejected"] = True
            elif valid_ack and status == "accepted" and s["evidence"]:
                s["accepted_after_evidence"] = True
        trace.append({"index": index, "op_id": op, "type": kind,
                      "accepted_after_evidence": s["accepted_after_evidence"],
                      "terminal_rejected": s["terminal_rejected"]})
    verdicts = {}
    for op, s in state.items():
        if s["terminal_rejected"]:
            verdict = "rejected"
        elif s["accepted_after_evidence"]:
            verdict = "accepted"
        else:
            verdict = "UNKNOWN"
        verdicts[op] = verdict
    return verdicts, trace

def main():
    doc = json.loads(CASES.read_text(encoding="utf-8"))
    records = []
    for case in doc["cases"]:
        actual, trace = classify(case["events"])
        expected = case["expected"]
        records.append({"id": case["id"], "title": case["title"],
                        "expected": expected, "actual": actual,
                        "pass": actual == expected, "trace": trace})
    result = {"synthetic_only": True, "production_verified": False,
              "schema_version": "S31-results-1", "worker_count": 1,
              "op_ids": ["A", "B"], "case_count": len(records),
              "pass_count": sum(r["pass"] for r in records),
              "fail_count": sum(not r["pass"] for r in records),
              "verdict_counts": {v: sum(r["actual"][op] == v for r in records for op in ("A", "B"))
                                 for v in ("accepted", "rejected", "UNKNOWN")},
              "records": records}
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    print(f"S31_STATS cases={result['case_count']} passes={result['pass_count']} fails={result['fail_count']} op_verdicts={sum(result['verdict_counts'].values())} counts={result['verdict_counts']}")
    raise SystemExit(0 if result["fail_count"] == 0 else 1)

if __name__ == "__main__":
    main()
