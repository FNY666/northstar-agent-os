#!/usr/bin/env python3
"""S25 deterministic offline synthetic restart-window harness.
Only models local simulated journal state; it makes no production claims.
"""
import argparse, hashlib, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent
FIX = ROOT / "fixtures" / "cases.json"
OUT = ROOT / "outputs" / "results.json"
WORKER = "worker-s25-01"
OP = "op-s25-0001"


def load():
    doc = json.loads(FIX.read_text())
    assert doc["synthetic_only"] is True and doc["production_verified"] is False
    assert doc["worker_id"] == WORKER and doc["op_id"] == OP
    return doc


def classify(c):
    a1, a2 = c["attempt1"], c["attempt2"]
    # Local-only rules: a record present before the simulated restart is the
    # only anchor. Response-before-record is never upgraded by this harness.
    if c["boundary"] == "response-before-record":
        return "UNKNOWN", "response existed without local record at simulated restart"
    if c["boundary"] == "before-record":
        if not a1["record_written"] and not a1["response_emitted"] and a2["record_written"]:
            if a2["response_ref"] == a2["durable_ref"]:
                return "accepted", "attempt-1 local journal was empty; attempt-2 refs equal"
            return "UNKNOWN", "attempt-2 response_ref and durable_ref differ"
        return "UNKNOWN", "unexpected local pre-restart state"
    if c["boundary"] == "record-before-response":
        if a1["record_written"] and a1["durable_ref"]:
            if a2["value"] != a1["value"]:
                return "rejected", "pre-restart local record value differs from attempt-2 value"
            if a2["response_ref"] != a2["durable_ref"]:
                return "UNKNOWN", "attempt-2 response_ref and durable_ref differ"
            if a2["durable_ref"] != a1["durable_ref"]:
                return "UNKNOWN", "durable_ref changed across simulated restart"
            return "accepted", "same pre-restart local value and equal stable refs"
        return "UNKNOWN", "no qualifying local record before restart"
    return "UNKNOWN", "unrecognized boundary"


def run():
    doc = load()
    rows = []
    for c in doc["cases"]:
        result, reason = classify(c)
        rows.append({
            "fixture_id": c["id"], "worker_id": WORKER, "op_id": OP,
            "attempts": [1, 2], "boundary": c["boundary"],
            "value_relation": c["value_relation"], "ref_relation": c["ref_relation"],
            "local_journal": {
                "attempt_1": {"record_written": c["attempt1"]["record_written"], "response_emitted": c["attempt1"]["response_emitted"], "value": c["attempt1"]["value"], "response_ref": c["attempt1"]["response_ref"], "durable_ref": c["attempt1"]["durable_ref"]},
                "attempt_2": {"record_written": c["attempt2"]["record_written"], "response_emitted": c["attempt2"]["response_emitted"], "value": c["attempt2"]["value"], "response_ref": c["attempt2"]["response_ref"], "durable_ref": c["attempt2"]["durable_ref"]},
            },
            "classification": result, "classification_basis": reason,
            "expected_fixture_classification": c["expected"],
            "matches_expected": result == c["expected"]
        })
    counts = {k: sum(r["classification"] == k for r in rows) for k in ["accepted", "rejected", "UNKNOWN"]}
    result = {"schema_version":"S25-results-1", "synthetic_only":True, "production_verified":False, "scope":"offline synthetic restart-window slice", "worker_id":WORKER, "op_id":OP, "simulated_crash_restart":True, "counts":counts, "all_expected_match":all(r["matches_expected"] for r in rows), "cases":rows, "disclaimer":"Local simulated journal states only; not evidence about real crash durability, remote state, exactly-once, rollback, or production safety."}
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"output":str(OUT),"case_count":len(rows),"counts":counts,"all_expected_match":result["all_expected_match"]}, ensure_ascii=False, sort_keys=True))
    return 0 if result["all_expected_match"] else 1


def validate():
    d = json.loads(OUT.read_text())
    assert d["synthetic_only"] is True and d["production_verified"] is False
    assert d["worker_id"] == WORKER and d["op_id"] == OP and len(d["cases"]) >= 10
    assert set(d["counts"]) == {"accepted", "rejected", "UNKNOWN"}
    assert sum(d["counts"].values()) == len(d["cases"])
    assert d["all_expected_match"] is True
    for r in d["cases"]:
        assert r["attempts"] == [1, 2] and r["classification"] in {"accepted","rejected","UNKNOWN"}
        assert r["matches_expected"] is True
        assert set(r["local_journal"]) == {"attempt_1","attempt_2"}
    print(json.dumps({"validator":"PASS","cases":len(d["cases"]),"counts":d["counts"]}, sort_keys=True))


def manifest_validate():
    m = json.loads((ROOT/"research-manifest.json").read_text())
    required = {"REPORT.md","sources.md","research-manifest.json","SHA256SUMS","harness.py","fixtures/cases.json","outputs/results.json"}
    assert m["synthetic_only"] is True and m["production_verified"] is False
    assert set(m["required_artifacts"]) == required
    assert m["worker_id"] == WORKER and m["op_id"] == OP
    assert m["network_access"] is False and m["real_services_accessed"] is False
    for p in required:
        assert (ROOT/p).exists(), p
    print(json.dumps({"manifest_validator":"PASS","required_artifacts":len(required)}, sort_keys=True))

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("command", choices=["run","validate","manifest-validate"]); a=ap.parse_args()
    if a.command == "run": sys.exit(run())
    if a.command == "validate": validate()
    else: manifest_validate()
