#!/usr/bin/env python3
"""Independent S36 validator: checks matrix semantics and exact mutation scope."""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "outputs" / "results.json"
CASES = ROOT / "fixtures" / "cases.json"


def fail(message):
    print(f"FAIL: {message}")
    raise SystemExit(1)


def main():
    data = json.loads(RESULTS.read_text(encoding="utf-8"))
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    if data.get("synthetic_only") is not True or data.get("production_verified") is not False:
        fail("provenance flags incorrect")
    if data["fixture_count"] != len(cases) or len(cases) < 20:
        fail("fixture count mismatch or below minimum")
    if set(data["operation_set"]) != {"P", "Q", "R", "X"}:
        fail("operation set mismatch")
    baseline = data["pairs"]["baseline"]
    mutated = data["pairs"]["mutated"]
    if baseline["conflict_count"] != 0 or baseline["conflict_fixtures"]:
        fail("baseline control is not all INTEROP_OK")
    expected_theory = [c["id"] for c in cases if "R" in c["operations"]]
    observed = mutated["conflict_fixtures"]
    if set(observed) != set(expected_theory):
        fail("mutated conflict scope differs from theoretical R scope")
    if mutated["unobservable_fixtures"]:
        fail("unexpected unobservable fixture(s) for this complete fixture set")
    for pair_name, pair in (("baseline", baseline), ("mutated", mutated)):
        if len(pair["results"]) != len(cases):
            fail(f"{pair_name} result row count mismatch")
        for row, case in zip(pair["results"], cases):
            if row["fixture_id"] != case["id"]:
                fail(f"{pair_name} fixture ordering mismatch")
            canonical = json.dumps(case, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
            if row["canonical_input_sha256"] != hashlib.sha256(canonical).hexdigest():
                fail(f"canonical SHA mismatch for {row['fixture_id']}")
            expected = "INTEROP_CONFLICT" if row["fixture_id"] in pair["conflict_fixtures"] else "INTEROP_OK"
            if row["status"] != expected or row["conflict"] != (expected == "INTEROP_CONFLICT"):
                fail(f"status/conflict mismatch for {row['fixture_id']}")
            if pair_name == "mutated" and "R" in case["operations"] and row["status"] != "INTEROP_CONFLICT":
                fail(f"UNKNOWN->accepted not caught for {row['fixture_id']}")
    print(f"PASS: validator fixture_count={len(cases)}")
    print("PASS: validator baseline all INTEROP_OK")
    print(f"PASS: validator mutated conflict scope exact ({len(observed)} fixtures)")
    print("PASS: validator canonical input SHA-256 checks")
    print("PASS: validator UNKNOWN->accepted upgrades are conflicts")


if __name__ == "__main__":
    main()
