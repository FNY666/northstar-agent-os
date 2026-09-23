#!/usr/bin/env python3
# synthetic_only=true; production_verified=false
"""S24 deterministic synthetic-only single-worker boundary harness."""
import json, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures" / "cases.json"
OUTPUT = ROOT / "outputs" / "results.json"


def fingerprint(item):
    return tuple(item[k] for k in ("attempt", "value", "response_ref", "durable_ref"))


def run_case(case):
    # One worker, one op_id. The attempt is part of the local identity; no
    # cross-attempt deduplication is inferred. An exact repeated arrival within
    # an attempt is accepted iff its full local record matches the first one.
    local = {}
    history = []
    outcomes = []
    for arrival in case["arrivals"]:
        attempt = arrival["attempt"]
        fp = fingerprint(arrival)
        if attempt not in local:
            local[attempt] = fp
            outcome = arrival["observation"]
            history.append({"attempt": attempt, "fingerprint": list(fp), "outcome": outcome})
        elif local[attempt] == fp:
            outcome = arrival["observation"]
        else:
            outcome = "rejected"
        outcomes.append(outcome)
    expected = case["expected_outcomes"]
    if outcomes != expected:
        raise AssertionError(f'{case["id"]}: {outcomes!r} != {expected!r}')
    exp_hist = case.get("expected_history_outcomes")
    if exp_hist is not None and [x["outcome"] for x in history] != exp_hist:
        raise AssertionError(f'{case["id"]}: history mismatch')
    return {"id": case["id"], "outcomes": outcomes, "history": history,
            "final_local_attempts": sorted(local), "status": "PASS"}


def main():
    data = json.loads(FIXTURES.read_text())
    assert data["synthetic_only"] is True and data["production_verified"] is False
    results = [run_case(c) for c in data["cases"]]
    counts = {"accepted": 0, "rejected": 0, "UNKNOWN": 0}
    for result in results:
        for outcome in result["outcomes"]:
            counts[outcome] += 1
    envelope = {
        "synthetic_only": True,
        "production_verified": False,
        "harness": "S24-v1-single-worker-single-op_id",
        "rules": {
            "worker_count": 1, "op_id_count": 1,
            "attempts": [1, 2],
            "same_attempt_exact_replay": "accepted or preserves supplied UNKNOWN",
            "same_attempt_field_change": "rejected",
            "attempt_boundary": "new local record; no cross-attempt dedup inference",
            "unknown_boundary": "UNKNOWN remains local observation for its attempt"
        },
        "fixture_count": len(results),
        "arrival_count": sum(len(x["outcomes"]) for x in results),
        "outcome_counts": counts,
        "results": results,
    }
    raw = json.dumps(envelope, ensure_ascii=False, indent=2) + "\n"
    OUTPUT.write_text(raw)
    print(raw, end="")

if __name__ == "__main__":
    main()
