#!/usr/bin/env python3
"""Offline deterministic provenance stress harness; stdlib only, no network."""
import hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = ROOT / "fixtures" / "cases.json"
OUT = ROOT / "outputs" / "results.json"

def canon(v):
    return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def sha(v):
    return hashlib.sha256(canon(v).encode()).hexdigest()

def evaluate(case):
    kind = case["kind"]; inp = case["input"]
    sources = inp.get("sources", [])
    provenance = [{"source_id": s.get("id"), "fingerprint": s.get("fingerprint"),
                   "payload_hash": sha(s.get("content")), "accessible": s.get("accessible", True)}
                  for s in sources]
    status = "UNKNOWN"; confidence = "low"; reason = "Evidence is insufficient for a rule-verified recovery."
    blocker = "No blocking condition recorded."
    if kind == "direct_complete":
        s = sources[0] if len(sources) == 1 else {}
        if s.get("accessible", True) and s.get("fingerprint") and s.get("content") == inp.get("expected_content"):
            status, confidence = "RECOVERED", "high"
            reason = "One accessible source has complete provenance and exact content match."
            blocker = "None under the synthetic rule set."
        else:
            reason = "Direct evidence did not satisfy the complete-provenance rule."
            blocker = "Missing, inaccessible, or content-mismatched source."
    elif kind == "cross_source_mismatch":
        ids = {s.get("event_id") for s in sources}
        if len(ids) > 1:
            status, confidence = "REJECT", "high"
            reason = "The same correlation key resolves to incompatible immutable event IDs."
            blocker = "Rule-verifiable cross-source linkage contradiction."
        else:
            blocker = "Expected linkage mismatch was not present."
    elif kind == "fingerprint_reuse":
        by_fp = {}
        for s in sources: by_fp.setdefault(s.get("fingerprint"), set()).add(sha(s.get("content")))
        if any(len(hashes) > 1 for hashes in by_fp.values()):
            status, confidence = "REJECT", "high"
            reason = "A source fingerprint is reused for different payloads."
            blocker = "Rule-verifiable fingerprint-to-payload contradiction."
        else: blocker = "Fingerprint reuse contradiction not established."
    elif kind == "same_summary_heterogeneous":
        by_summary = {}
        for s in sources: by_summary.setdefault(s.get("summary"), set()).add(sha(s.get("content")))
        if any(len(hashes) > 1 for hashes in by_summary.values()):
            status, confidence = "REJECT", "high"
            reason = "Identical summary text maps to heterogeneous content."
            blocker = "Rule-verifiable summary/content contradiction."
        else: blocker = "Heterogeneous content was not established."
    elif kind == "replay_order_inversion":
        seq = [s.get("sequence") for s in sources]
        if seq != sorted(seq):
            status, confidence = "REJECT", "high"
            reason = "Replay sequence violates the declared strict monotonic-order invariant."
            blocker = "Rule-verifiable replay-order contradiction."
        else: blocker = "Strict order inversion not established."
    elif kind == "clock_boundary":
        drift, bound = inp.get("drift_seconds"), inp.get("allowed_seconds")
        if drift <= bound:
            status, confidence = "RECOVERED", "medium"
            reason = "Observed clock drift is exactly within the declared inclusive boundary."
            blocker = "None under the synthetic inclusive-boundary rule."
        else: blocker = "Drift exceeds the allowed boundary; no contradictory event value is proven."
    elif kind == "explicit_contradiction":
        status, confidence = "REJECT", "high"
        reason = "The fixture contains an explicit contradiction against a declared invariant."
        blocker = "Rule-verifiable invariant contradiction."
    elif kind == "stable_fingerprint":
        if len(sources) == 2 and sources[0].get("fingerprint") == sources[1].get("fingerprint") and sha(sources[0].get("content")) == sha(sources[1].get("content")):
            status, confidence = "RECOVERED", "medium"
            reason = "Repeated observations agree on fingerprint and payload hash."
            blocker = "None under the synthetic repeat-agreement rule."
        else: blocker = "Repeat agreement is incomplete."
    elif kind == "partial_provenance":
        reason = "Payload is present but its provenance chain is incomplete."
        blocker = "Missing source fingerprint or event linkage."
    elif kind == "budget_truncation":
        reason = "The evidence stream is explicitly truncated by the collection budget."
        blocker = "Unobserved tail could change the conclusion."
    elif kind == "missing_evidence":
        reason = "No evidence was supplied for the asserted event."
        blocker = "Evidence absence is not evidence of a negative result."
    elif kind == "inaccessible":
        reason = "A referenced source is marked inaccessible in the fixture."
        blocker = "Source cannot be independently inspected."
    elif kind == "ambiguous_linkage":
        reason = "More than one candidate linkage remains plausible."
        blocker = "No deterministic disambiguator is present."
    elif kind == "majority_vote_trap":
        reason = "Conflicting observations cannot be promoted by majority vote alone."
        blocker = "No rule-authorized source authority or contradiction resolution."
    elif kind == "retry_no_change":
        reason = "Retries reproduce the same incomplete evidence; retry count is not provenance."
        blocker = "No new independent evidence after replay."
    elif kind == "complete_but_unverified":
        reason = "Fields are syntactically complete, but the claimed relation is not rule-verifiable."
        blocker = "Semantic verification rule is absent."
    result = {
        "id": case["id"], "status": status, "confidence": confidence,
        "provenance": provenance, "reason": reason, "blocker": blocker,
        "input_hash": sha(case["input"]), "synthetic_only": True,
        "production_verified": False, "rule_set": "S15-v1-local-deterministic"
    }
    return result

def main():
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    if len(cases) < 16: raise SystemExit("need at least 16 fixtures")
    results = [evaluate(c) for c in cases]
    payload = {"schema_version":"S15-results-v1", "synthetic_only":True, "production_verified":False,
               "case_count":len(results), "results":results}
    OUT.write_text(canon(payload) + "\n", encoding="utf-8")
    counts = {s: sum(r["status"] == s for r in results) for s in ("RECOVERED","UNKNOWN","REJECT")}
    print(json.dumps({"case_count":len(results), "counts":counts, "output":str(OUT)}, sort_keys=True))
if __name__ == "__main__": main()
