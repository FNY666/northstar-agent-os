#!/usr/bin/env python3
"""Deterministic, offline synthetic evidence-state-machine harness.
No network, credentials, SDKs, or real platform calls are used.
synthetic_only=true
production_verified=false
"""
import argparse, hashlib, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent
CASES = ROOT / "fixtures" / "cases.json"
RESULTS = ROOT / "outputs" / "results.json"
SYNTHETIC_ONLY = True
PRODUCTION_VERIFIED = False
OPERATION_ID = "op-s8-20260922-fixed-0001"
PAYLOAD = {"action":"conditional-write","resource":"synthetic/object/alpha","value":"S8-fixed-payload-v1"}
DIGEST = hashlib.sha256(json.dumps(PAYLOAD, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def canon(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"))


def classify(c, events):
    kind = c["kind"]
    if kind in {"k8s_rv_409", "s3_412", "s3_409", "gcs_412", "azure_etag_412", "azure_lease_412", "azure_lease_409"}:
        state = "PRECONDITION_CONFLICT"
        action = "retry_after_fresh_read_or_compensate"
        ev_status = "confirmed"
        w = None
    elif kind in {"permission_403", "permission_401"}:
        state = "PERMISSION_DENIED"
        action = "stop_and_request_authorization_or_human_review"
        ev_status = "confirmed"
        w = None
    elif kind == "response_lost":
        state = "AMBIGUOUS_COMMIT"
        action = "retry_same_operation_only_then_read_back"
        ev_status = "inferred"
        w = c.get("synthetic_w_ms")
    elif kind in {"old_read_cache", "old_read_generation"}:
        state = "VISIBILITY_UNKNOWN"
        action = "do_not_claim_success; widen_window_or_human_review"
        ev_status = "unverified"
        w = None
    elif kind == "duplicate_retry":
        state = "DUPLICATE_ATTEMPT"
        action = "dedupe_by_operation_and_digest; verify_read_back"
        ev_status = "inferred"
        w = c.get("synthetic_w_ms")
    elif kind == "status_only_409":
        state = "AMBIGUOUS_CONFLICT"
        action = "require_platform_and_precondition_context"
        ev_status = "conflicting"
        w = None
    elif kind == "payload_digest_mismatch":
        state = "IDENTITY_MISMATCH"
        action = "block_retry_and_escalate"
        ev_status = "conflicting"
        w = None
    elif kind == "real_service_probe":
        state = "INACCESSIBLE"
        action = "do_not_probe; keep synthetic-only"
        ev_status = "inaccessible"
        w = None
    else:
        state = "UNKNOWN"
        action = "human_review"
        ev_status = "unverified"
        w = None
    readback = c.get("read_back", {})
    rb_state = readback.get("state", "not_attempted")
    if w is not None and rb_state == "matched":
        terminal = "CONFIRMED_BY_SYNTHETIC_READ_BACK"
    elif state in {"PRECONDITION_CONFLICT", "PERMISSION_DENIED", "IDENTITY_MISMATCH", "AMBIGUOUS_CONFLICT", "INACCESSIBLE"}:
        terminal = state
    else:
        terminal = "UNKNOWN"
    return {
        "case_id": c["case_id"], "platform": c["platform"], "kind": kind,
        "operation_id": OPERATION_ID, "payload_sha256": DIGEST,
        "evidence_status": ev_status, "state": state, "terminal": terminal,
        "action": action, "events": events, "read_back": readback,
        "W_ms": w if (w is not None and rb_state == "matched") else "UNKNOWN",
        "synthetic_only": True, "production_verified": False,
        "notes": c.get("notes", "")
    }


def run():
    cases = json.loads(CASES.read_text())
    if cases.get("synthetic_only") is not True or cases.get("production_verified") is not False:
        raise SystemExit("fixture trust flags invalid")
    out = []
    for c in cases["cases"]:
        if c["operation_id"] != OPERATION_ID or c["payload_sha256"] != DIGEST:
            raise SystemExit(f"fixed identity mismatch: {c['case_id']}")
        events = c.get("events", [])
        out.append(classify(c, events))
    stats = {"total": len(out), "by_evidence_status": {}, "by_terminal": {},
             "unknown_case_ids": [], "W_ms_matched": {}}
    for r in out:
        stats["by_evidence_status"][r["evidence_status"]] = stats["by_evidence_status"].get(r["evidence_status"], 0) + 1
        stats["by_terminal"][r["terminal"]] = stats["by_terminal"].get(r["terminal"], 0) + 1
        if r["terminal"] == "UNKNOWN": stats["unknown_case_ids"].append(r["case_id"])
        if r["W_ms"] != "UNKNOWN": stats["W_ms_matched"][r["case_id"]] = r["W_ms"]
    result = {"schema_version":"s8-results-1.0", "synthetic_only":True,
              "production_verified":False, "operation_id":OPERATION_ID,
              "payload":PAYLOAD, "payload_sha256":DIGEST,
              "measurement":{"W_definition":"first synthetic read-back event t >= write acceptance with matching operation_id and payload_sha256; UNKNOWN if absent or stale","clock":"logical milliseconds; not wall-clock or durability evidence"},
              "stats":stats, "cases":out}
    RESULTS.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"written":str(RESULTS), "stats":stats, "operation_id":OPERATION_ID, "payload_sha256":DIGEST}, indent=2, sort_keys=True))


def validate():
    x = json.loads(RESULTS.read_text())
    errors=[]
    if x.get("synthetic_only") is not True or x.get("production_verified") is not False: errors.append("root trust flags")
    if x.get("operation_id") != OPERATION_ID or x.get("payload_sha256") != DIGEST: errors.append("fixed identity")
    if len(x.get("cases",[])) != x.get("stats",{}).get("total"): errors.append("count")
    allowed={"confirmed","inferred","unverified","conflicting","inaccessible"}
    for r in x.get("cases",[]):
        if r.get("evidence_status") not in allowed: errors.append(r.get("case_id","?")+":status")
        if r.get("synthetic_only") is not True or r.get("production_verified") is not False: errors.append(r.get("case_id","?")+":flags")
        if r.get("operation_id") != OPERATION_ID or r.get("payload_sha256") != DIGEST: errors.append(r.get("case_id","?")+":identity")
    calc={}
    for r in x.get("cases",[]): calc[r["evidence_status"]]=calc.get(r["evidence_status"],0)+1
    if calc != x["stats"]["by_evidence_status"]: errors.append("status stats")
    if errors: print("VALIDATOR: FAIL", json.dumps(errors)); return 1
    print("VALIDATOR: PASS cases=%d unknown=%d" % (x["stats"]["total"], len(x["stats"]["unknown_case_ids"])))
    return 0

if __name__ == "__main__":
    ap=argparse.ArgumentParser(); ap.add_argument("--validate", action="store_true")
    a=ap.parse_args(); sys.exit(validate() if a.validate else (run() or 0))
