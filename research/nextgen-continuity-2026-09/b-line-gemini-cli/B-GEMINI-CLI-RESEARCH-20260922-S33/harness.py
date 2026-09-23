#!/usr/bin/env python3
"""Offline deterministic synthetic-only S33 trace harness."""
import hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = ROOT / "fixtures" / "cases.json"
OUT = ROOT / "outputs" / "results.json"
KNOWN = {"P", "Q", "R"}
ALL_OPS = ["P", "Q", "R", "X"]

def canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def sha(obj):
    return hashlib.sha256(canon(obj).encode("utf-8")).hexdigest()

def evaluate(case):
    events = case["input"]["events"]
    epochs = case["input"]["epochs"]
    ops = case["input"].get("ops", ALL_OPS)
    by = {(op, ep): [] for op in ops for ep in epochs}
    refs = {}
    for row in events:
        op, ep = row["op"], row["epoch"]
        by.setdefault((op, ep), []).append(row)
        if row["kind"] == "event":
            refs[row["seq"]] = row
    # A repeated payload is not fresh evidence after the first accepted epoch.
    accepted_payloads = {}
    judgments = []
    for ep in epochs:
        for op in ops:
            rows = by.get((op, ep), [])
            evs = [r for r in rows if r["kind"] == "event"]
            acks = [r for r in rows if r["kind"] == "ack"]
            revokes = [r for r in rows if r["kind"] == "revoke"]
            conflicts = [r for r in rows if r["kind"] == "conflict"]
            blockers = []
            reason = ""
            verdict = "UNKNOWN"
            if op not in KNOWN:
                reason = "operation is undeclared; its complete-looking trace is quarantined"
                blockers = ["unknown_op"]
            elif conflicts:
                verdict = "rejected"
                reason = "explicit same-epoch contradiction record"
                blockers = ["explicit_contradiction"]
            elif revokes:
                reason = "epoch is explicitly revoked; revocation is not rejection"
                blockers = ["revoked_epoch"]
            elif not evs and not acks:
                reason = "no evidence for this operation and epoch"
                blockers = ["missing_event", "missing_ack"]
            elif not evs:
                reason = "ack has no same-epoch event"
                blockers = ["missing_event"]
            elif not acks:
                reason = "event evidence is present but acknowledgement is absent"
                blockers = ["missing_ack"]
            else:
                # Every same-epoch candidate must be paired by exact reference.
                paired = []
                for ev in evs:
                    for ack in acks:
                        if ack.get("ref_event_seq") == ev["seq"]:
                            paired.append((ev, ack))
                if not paired:
                    cross = [a for a in acks if a.get("ref_event_seq") in refs and refs[a["ref_event_seq"]]["epoch"] != ep]
                    if cross:
                        reason = "ack arrived in a later/different epoch and cannot upgrade prior evidence"
                        blockers = ["delayed_ack", "cross_epoch_reference"]
                    elif any(a.get("seq", 0) < e.get("seq", 0) for e in evs for a in acks):
                        reason = "ack/event ordering is reversed"
                        blockers = ["reordered"]
                    else:
                        reason = "event and acknowledgement do not form a same-epoch pair"
                        blockers = ["stale_or_unmatched_ack"]
                else:
                    ev, ack = paired[0]
                    payload = ev.get("payload")
                    if ack.get("seq", 0) < ev.get("seq", 0):
                        reason = "ack arrived before its event"
                        blockers = ["reordered"]
                    elif ev.get("stale") or ack.get("stale"):
                        reason = "stale evidence is not eligible for upgrade"
                        blockers = ["stale"]
                    elif payload in accepted_payloads.get(op, set()):
                        reason = "same operation/payload was already accepted in an earlier epoch; repeat is not new evidence"
                        blockers = ["duplicate_payload"]
                    else:
                        verdict = "accepted"
                        reason = "same-epoch event and acknowledgement are complete and ordered"
                        blockers = []
                        accepted_payloads.setdefault(op, set()).add(payload)
            judgments.append({"epoch": ep, "op": op, "verdict": verdict,
                              "reason": reason, "blocking_conditions": blockers})
    return {"fixture_id": case["id"], "epoch_sequence": epochs,
            "op_judgments": judgments, "canonical_input_sha256": sha(case["input"]),
            "synthetic_only": True, "production_verified": False}

def main():
    data = json.loads(CASES.read_text(encoding="utf-8"))
    results = [evaluate(c) for c in data["fixtures"]]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"synthetic_only": True, "production_verified": False,
                               "fixture_count": len(results), "results": results},
                              ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    counts = {k: 0 for k in ("accepted", "rejected", "UNKNOWN")}
    for r in results:
        for j in r["op_judgments"]: counts[j["verdict"]] += 1
    print(f"PASS: harness deterministic serialization; fixtures={len(results)}")
    print(f"PASS: verdicts accepted={counts['accepted']} rejected={counts['rejected']} UNKNOWN={counts['UNKNOWN']}")
    print(f"PASS: wrote outputs/results.json; result_rows={sum(len(r['op_judgments']) for r in results)}")
    return 0
if __name__ == "__main__": sys.exit(main())
