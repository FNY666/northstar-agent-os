#!/usr/bin/env python3
"""Offline deterministic DAG replay harness for S22 synthetic fixtures."""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASE_FILE = ROOT / "fixtures" / "cases.json"

VALID_STATES = {"RECOVERED", "UNKNOWN", "REJECT"}
CLASSIFICATIONS = {"NO_EVENT", "DELAYED", "DROPPED", "EXPORTER_FAILURE", "QUERY_GAP", "RETENTION_EXPIRED", "VERIFIED_CONTINUITY", "UNKNOWN"}


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(obj):
    return hashlib.sha256(canonical(obj).encode()).hexdigest()


def event_map(events):
    out = {}
    conflicts = []
    for ev in events:
        eid = ev.get("id")
        if not isinstance(eid, str) or not eid:
            conflicts.append("MALFORMED_EVENT_ID")
            continue
        if eid in out and canonical(out[eid]) != canonical(ev):
            conflicts.append("DUPLICATE_CONFLICT")
        else:
            out[eid] = ev
    return out, conflicts


def evidence_index(values):
    out = {}
    for rec in values or []:
        eid = rec.get("event_id")
        if eid is not None and eid not in out:
            out[eid] = rec.get("status")
    return out


def replay(case):
    snap = case.get("snapshot") or {}
    inc = case.get("incrementals") or []
    evidence = case.get("evidence") or {}
    signals = set(case.get("signals") or [])
    state = "RECOVERED"
    reasons = []
    classifications = []

    def unknown(reason, classification=None):
        nonlocal state
        if state != "REJECT":
            state = "UNKNOWN"
        reasons.append(reason)
        if classification and classification not in classifications:
            classifications.append(classification)

    def reject(reason):
        nonlocal state
        state = "REJECT"
        reasons.append(reason)

    if snap.get("complete") is not True:
        unknown("INCOMPLETE_SNAPSHOT", "QUERY_GAP")
    required_pages = set(snap.get("required_pages") or [])
    actual_pages = {p.get("id") for p in snap.get("pages") or []}
    if not required_pages.issubset(actual_pages):
        unknown("MISSING_PAGE", "QUERY_GAP")
    required_shards = set(snap.get("required_shards") or [])
    actual_shards = {p.get("shard") for p in snap.get("pages") or []}
    if not required_shards.issubset(actual_shards):
        unknown("MISSING_SHARD", "QUERY_GAP")
    if snap.get("retention_expired") is True:
        unknown("RETENTION_EXPIRED", "RETENTION_EXPIRED")

    snapshot_events = []
    for page in snap.get("pages") or []:
        snapshot_events.extend(page.get("events") or [])
    smap, conflicts = event_map(snapshot_events)
    for reason in conflicts:
        reject(reason)
    all_events = list(smap.values())
    imap, conflicts = event_map(inc)
    for reason in conflicts:
        reject(reason)
    for eid, ev in imap.items():
        if eid in smap and canonical(smap[eid]) != canonical(ev):
            reject("SNAPSHOT_INCREMENT_CONFLICT")
        all_events.append(ev)

    versions = {snap.get("version")} | {ev.get("version") for ev in all_events}
    versions.discard(None)
    if len(versions) != 1 or (versions and snap.get("version") not in versions):
        reject("VERSION_DRIFT")

    start, end = snap.get("boundary_start"), snap.get("boundary_end")
    for ev in all_events:
        ts = ev.get("ts")
        if isinstance(start, (int, float)) and isinstance(ts, (int, float)) and ts < start:
            reject("BOUNDARY_OUTSIDE_BEFORE")
        if isinstance(end, (int, float)) and isinstance(ts, (int, float)) and ts > end:
            reject("BOUNDARY_OUTSIDE_AFTER")
        if ev.get("contradicts"):
            reject("EXPLICIT_CONTRADICTION")

    known_ids = set(smap) | set(imap)
    boundary_anchors = set(snap.get("boundary_anchors") or [])
    for ev in inc:
        for parent in ev.get("parents") or []:
            if parent not in known_ids and parent not in boundary_anchors:
                unknown("DAG_PARENT_GAP", "QUERY_GAP")

    # A checkpoint resumes at last_seq+1. Ordering is normalized, but missing
    # sequence numbers are not invented: the gate fails closed to UNKNOWN.
    last_seq = snap.get("last_seq")
    seqs = sorted({ev.get("seq") for ev in inc if isinstance(ev.get("seq"), int)})
    if inc and isinstance(last_seq, int):
        expected = list(range(last_seq + 1, last_seq + 1 + len(seqs)))
        if seqs != expected:
            unknown("SEQUENCE_GAP", "QUERY_GAP")
    if case.get("checkpoint", {}).get("resume_from") is not None and case["checkpoint"].get("resume_from") != last_seq:
        unknown("CHECKPOINT_MISMATCH", "QUERY_GAP")

    # Evidence channels are independent: a platform receipt is not a log and
    # a log is not confirmation of an external effect.
    receipts = evidence_index(evidence.get("platform_receipts"))
    logs = evidence_index(evidence.get("logs"))
    effects = evidence_index(evidence.get("external_effects"))
    for sig, cls in (("exporter_failure", "EXPORTER_FAILURE"), ("query_gap", "QUERY_GAP"), ("retention_expired", "RETENTION_EXPIRED"), ("delayed", "DELAYED"), ("dropped", "DROPPED")):
        if sig in signals:
            unknown(sig.upper(), cls)
    if "unknown" in signals:
        unknown("UNCLASSIFIED_EVIDENCE", "UNKNOWN")

    if not inc and case.get("no_event_attestation") is True:
        classifications.append("NO_EVENT")
    elif not inc:
        unknown("NO_INCREMENTAL_ATTESTATION", "NO_EVENT")

    for ev in inc:
        eid = ev.get("id")
        if receipts.get(eid) != "accepted":
            unknown("PLATFORM_RECEIPT_NOT_ACCEPTED:" + str(eid), "DROPPED" if receipts.get(eid) == "dropped" else "UNKNOWN")
        if logs.get(eid) != "present":
            unknown("LOG_NOT_PRESENT:" + str(eid), "EXPORTER_FAILURE" if logs.get(eid) == "exporter_failure" else "UNKNOWN")
        if effects.get(eid) != "confirmed":
            unknown("EXTERNAL_EFFECT_NOT_CONFIRMED:" + str(eid), "DELAYED" if effects.get(eid) == "delayed" else "UNKNOWN")

    if state == "RECOVERED":
        classifications.append("VERIFIED_CONTINUITY")
    # Stable order is part of the artifact contract.
    ordered = [c for c in ("NO_EVENT", "DELAYED", "DROPPED", "EXPORTER_FAILURE", "QUERY_GAP", "RETENTION_EXPIRED", "VERIFIED_CONTINUITY", "UNKNOWN") if c in classifications]
    if not ordered:
        ordered = ["UNKNOWN"] if state != "RECOVERED" else ["VERIFIED_CONTINUITY"]
    return {"id": case.get("id"), "state": state, "classifications": ordered, "reasons": sorted(set(reasons)), "input_digest": digest(case)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default=str(ROOT / "outputs" / "results.json"))
    args = ap.parse_args()
    data = json.loads(CASE_FILE.read_text(encoding="utf-8"))
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        print("FAIL: no cases", file=sys.stderr); return 2
    results = []
    for case in cases:
        got = replay(case)
        exp = case.get("expected") or {}
        if got["state"] != exp.get("state") or got["classifications"] != exp.get("classifications"):
            print("FAIL: expectation mismatch " + str(case.get("id")), file=sys.stderr)
            print(json.dumps({"got": got, "expected": exp}, ensure_ascii=False), file=sys.stderr)
            return 3
        results.append(got)
    counts = {s: sum(r["state"] == s for r in results) for s in sorted(VALID_STATES)}
    out = {"schema_version":"s22.results.v1", "synthetic_only":True, "production_verified":False, "fixture_digest":digest(data), "case_count":len(results), "state_counts":counts, "results":results}
    p = Path(args.output); p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"PASS: harness fixtures={len(results)} RECOVERED={counts['RECOVERED']} UNKNOWN={counts['UNKNOWN']} REJECT={counts['REJECT']}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
