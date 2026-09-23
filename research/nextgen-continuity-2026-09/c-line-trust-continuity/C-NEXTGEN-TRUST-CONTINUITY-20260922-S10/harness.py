#!/usr/bin/env python3
"""Deterministic, local-only crash-window/restart-recovery simulator.
synthetic_only=true
production_verified=false
"""
import hashlib, json, os, sys
from collections import defaultdict

SYNTHETIC_ONLY = True
PRODUCTION_VERIFIED = False
ROOT = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(ROOT, "fixtures", "cases.json")
OUT = os.path.join(ROOT, "outputs", "results.json")


def checksum(record_id, payload):
    body = f"{record_id}|{payload}".encode()
    return hashlib.sha256(body).hexdigest()[:16]


def encode(record_id, payload):
    return f"REC|{record_id}|{payload}|{checksum(record_id, payload)}".encode()


def parse(blob):
    try:
        text = blob.decode("ascii")
        parts = text.split("|")
        if len(parts) != 4 or parts[0] != "REC":
            return None, "malformed_or_partial"
        rid, payload, supplied = parts[1], parts[2], parts[3]
        if not rid or supplied != checksum(rid, payload):
            return None, "torn_or_checksum_mismatch"
        return {"record_id": rid, "payload": payload}, None
    except (UnicodeDecodeError, ValueError):
        return None, "malformed_or_partial"


def run_fixture(case):
    journal = []
    responses = []
    anomalies = []
    valid = defaultdict(list)
    crashed = False
    events = case["events"][: case.get("crash_after", 10**9)]
    if len(events) < len(case["events"]):
        crashed = True
    for event in events:
        kind = event["kind"]
        if kind == "record_attempt":
            mode = event["write_mode"]
            rid, payload = event["record_id"], event.get("payload", "")
            raw = encode(rid, payload)
            if mode == "complete":
                journal.append(raw)
            elif mode == "partial":
                journal.append(raw[: int(event.get("cut", len(raw)//2))])
            elif mode == "torn":
                torn = bytearray(raw)
                index = int(event.get("byte_index", len(torn)-1))
                torn[index] = ord("0") if torn[index] != ord("0") else ord("1")
                journal.append(bytes(torn))
            elif mode == "duplicate":
                journal.extend([raw, raw])
            elif mode == "conflict":
                journal.extend([raw, encode(rid, event["conflict_payload"])])
            elif mode == "none":
                pass
            elif mode == "inaccessible":
                anomalies.append({"type": "inaccessible_segment", "record_id": rid})
            else:
                anomalies.append({"type": "unknown_write_mode", "mode": mode})
        elif kind == "response":
            responses.append({"record_id": event["record_id"], "status": event["status"]})
        elif kind == "crash":
            crashed = True
            break
        else:
            anomalies.append({"type": "unknown_event", "kind": kind})

    # Restart replay is deterministic: parse only bytes that made it to journal.
    for raw in journal:
        rec, error = parse(raw)
        if rec is None:
            anomalies.append({"type": error})
        else:
            valid[rec["record_id"]].append(rec["payload"])
    target = case["target_record_id"]
    vals = valid.get(target, [])
    target_responses = [r for r in responses if r["record_id"] == target]
    response_ok = any(r["status"] == "ok" for r in target_responses)
    duplicate = len(vals) > 1 and len(set(vals)) == 1
    conflict = len(set(vals)) > 1
    invalid = bool(anomalies)
    inaccessible = any(a["type"] == "inaccessible_segment" for a in anomalies)

    # Decision semantics are deliberately local and explicit, not a production claim.
    if conflict:
        fail_closed = "REJECT"
        fail_open = "REJECT"  # confirmed contradictory data is not treated as unknown
    elif invalid or inaccessible:
        fail_closed = "UNKNOWN"
        fail_open = "ACCEPT"  # fail-open demonstrates unsafe assumption on unresolved state
    elif response_ok and len(vals) == 1:
        fail_closed = "ACCEPT"
        fail_open = "ACCEPT"
    elif response_ok and not vals:
        fail_closed = "UNKNOWN"
        fail_open = "ACCEPT"
    elif vals and not response_ok:
        fail_closed = "UNKNOWN"
        fail_open = "ACCEPT"
    elif duplicate:
        fail_closed = "UNKNOWN"  # replay observed, exactly-once remains unproven
        fail_open = "ACCEPT"
    else:
        fail_closed = "UNKNOWN"
        fail_open = "ACCEPT"

    residual = []
    if fail_closed == "UNKNOWN":
        residual.append("fail_closed decision unresolved by local evidence")
    if fail_open == "ACCEPT" and (invalid or inaccessible or not response_ok or duplicate or not vals):
        residual.append("fail_open accepted without complete continuity proof")
    if duplicate:
        residual.append("duplicate replay does not establish exactly-once")
    result = {
        "id": case["id"],
        "title": case["title"],
        "evidence_status": case["evidence_status"],
        "crash_window": case["crash_window"],
        "crashed_before_all_events": crashed,
        "journal_bytes": [b.decode("ascii", "replace") for b in journal],
        "replay_valid_records": {k: v for k, v in sorted(valid.items())},
        "responses_seen": responses,
        "anomalies": anomalies,
        "observed": {
            "target_record_id": target, "response_ok": response_ok,
            "record_count": len(vals), "duplicate_same_payload": duplicate,
            "conflicting_payloads": conflict, "inaccessible": inaccessible
        },
        "fail_closed": fail_closed,
        "fail_open": fail_open,
        "residual_unknown": residual,
        "local_interpretation": case["local_interpretation"],
        "production_claim": "not established by this synthetic run"
    }
    return result


def main():
    with open(CASES, encoding="utf-8") as f:
        doc = json.load(f)
    results = [run_fixture(c) for c in doc["fixtures"]]
    summary = {
        "fixtures": len(results),
        "fail_closed_counts": {s: sum(r["fail_closed"] == s for r in results) for s in ["ACCEPT", "REJECT", "UNKNOWN"]},
        "fail_open_counts": {s: sum(r["fail_open"] == s for r in results) for s in ["ACCEPT", "REJECT", "UNKNOWN"]},
        "residual_unknown_fixture_count": sum(bool(r["residual_unknown"]) for r in results),
        "evidence_status_counts": {s: sum(r["evidence_status"] == s for r in results) for s in ["confirmed", "inferred", "unverified", "conflicting", "inaccessible"]}
    }
    output = {
        "synthetic_only": SYNTHETIC_ONLY,
        "production_verified": PRODUCTION_VERIFIED,
        "explicit_flags": "synthetic_only=true; production_verified=false",
        "simulator": "deterministic-local-crash-window-v1",
        "scope": "offline synthetic journal/replay only",
        "summary": summary,
        "results": results,
        "limitations": [
            "Local journal/replay output cannot prove real crash durability.",
            "It cannot prove remote state, exactly-once, rollback, immutable audit, or production readiness.",
            "No network, service, credential, SDK, or external state was accessed."
        ]
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    for r in results:
        print(f"{r['id']}: fail_closed={r['fail_closed']} fail_open={r['fail_open']} status={r['evidence_status']} residual={len(r['residual_unknown'])}")

if __name__ == "__main__":
    main()
