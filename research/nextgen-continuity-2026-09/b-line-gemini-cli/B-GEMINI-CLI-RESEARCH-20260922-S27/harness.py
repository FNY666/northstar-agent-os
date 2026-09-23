#!/usr/bin/env python3
"""Deterministic, local-only crash-window simulator for S27."""
from __future__ import annotations
import json, sys
from pathlib import Path

SYNTHETIC_ONLY = True
PRODUCTION_VERIFIED = False
STAGES = ("record_append", "response_emission", "durable_reference_emission")
STATUSES = {"accepted", "rejected", "UNKNOWN"}


def fail(msg: str) -> None:
    raise ValueError(msg)


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate_cases(data):
    if data.get("synthetic_only") is not True or data.get("production_verified") is not False:
        fail("cases must declare synthetic_only=true and production_verified=false")
    if data.get("worker_count") != 1:
        fail("worker_count must be exactly 1")
    cases = data.get("fixtures")
    if not isinstance(cases, list) or len(cases) < 12:
        fail("at least 12 fixtures are required")
    ids, op_ids = set(), set()
    for c in cases:
        for key in ("fixture_id", "op_id", "order", "cut_stage", "cut_phase", "expected_status"):
            if key not in c:
                fail(f"fixture missing {key}")
        if c["fixture_id"] in ids:
            fail("duplicate fixture_id")
        ids.add(c["fixture_id"]); op_ids.add(c["op_id"])
        if tuple(c["order"]) not in __import__("itertools").permutations(STAGES):
            fail(f"invalid stage permutation in {c['fixture_id']}")
        if c["cut_stage"] not in STAGES or c["cut_phase"] not in ("before", "after"):
            fail(f"invalid cut in {c['fixture_id']}")
        if c["expected_status"] not in STATUSES:
            fail(f"invalid expected status in {c['fixture_id']}")
    if len(op_ids) != 1:
        fail("all fixtures must use one op_id")
    return cases


def simulate(case):
    op_id = case["op_id"]
    cut_index = case["order"].index(case["cut_stage"])
    stop = cut_index + (1 if case["cut_phase"] == "after" else 0)
    state = {"record_appended": False, "response_emitted": False,
             "durable_reference_emitted": False, "reference_valid": False}
    trace = []
    for idx, stage in enumerate(case["order"]):
        if idx >= stop:
            break
        if stage == "record_append":
            state["record_appended"] = True
        elif stage == "response_emission":
            state["response_emitted"] = True
        elif stage == "durable_reference_emission":
            state["durable_reference_emitted"] = True
            state["reference_valid"] = state["record_appended"]
        trace.append(stage)
    if state["reference_valid"] and state["record_appended"]:
        status = "accepted"
        reason = "record exists and reference was emitted after append"
    elif not any(state.values()):
        status = "rejected"
        reason = "crash occurred before any observable side effect"
    else:
        status = "UNKNOWN"
        reason = "partial or order-invalid evidence cannot decide acceptance"
    return {
        "fixture_id": case["fixture_id"], "op_id": op_id,
        "worker_count": 1, "crash_cut": {"stage": case["cut_stage"], "phase": case["cut_phase"]},
        "executed_stages": trace, "state": state, "classification": status,
        "reason": reason, "synthetic_only": True, "production_verified": False,
    }


def validate_results(data, cases):
    if data.get("synthetic_only") is not True or data.get("production_verified") is not False:
        fail("results must declare synthetic_only=true and production_verified=false")
    rows = data.get("results")
    if not isinstance(rows, list) or len(rows) != len(cases):
        fail("results count does not match fixtures")
    expected = {c["fixture_id"]: c for c in cases}
    seen = set()
    for row in rows:
        fid = row.get("fixture_id")
        if fid in seen or fid not in expected:
            fail("unexpected or duplicate result fixture")
        seen.add(fid)
        if row.get("classification") not in STATUSES:
            fail(f"invalid result status for {fid}")
        if row["classification"] != expected[fid]["expected_status"]:
            fail(f"expected-status mismatch for {fid}")
        if row.get("synthetic_only") is not True or row.get("production_verified") is not False:
            fail(f"result flags missing for {fid}")
    if seen != set(expected):
        fail("missing result fixture")


def main():
    root = Path(__file__).resolve().parent
    cases_path = root / "fixtures" / "cases.json"
    output_path = root / "outputs" / "results.json"
    if len(sys.argv) > 1 and sys.argv[1] == "--validate":
        cases = validate_cases(load_json(cases_path)); validate_results(load_json(output_path), cases)
        print(f"PASS: self-validator checked {len(cases)} deterministic fixtures")
        return
    cases = validate_cases(load_json(cases_path))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    results = [simulate(c) for c in cases]
    validate_results({"synthetic_only": True, "production_verified": False, "results": results}, cases)
    output_path.write_text(json.dumps({"schema_version": "S27-results-v1", "synthetic_only": True,
        "production_verified": False, "worker_count": 1, "op_id": cases[0]["op_id"],
        "result_count": len(results), "results": results}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    counts = {s: sum(r["classification"] == s for r in results) for s in sorted(STATUSES)}
    print(json.dumps({"output": str(output_path), "result_count": len(results), "counts": counts}, sort_keys=True))

if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr); raise SystemExit(1)
