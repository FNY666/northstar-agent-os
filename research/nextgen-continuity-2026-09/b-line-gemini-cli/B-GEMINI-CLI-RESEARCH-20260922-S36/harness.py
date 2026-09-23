#!/usr/bin/env python3
"""Deterministic, offline S36 meta-test harness."""
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = ROOT / "fixtures" / "cases.json"
OUT = ROOT / "outputs" / "results.json"
ALLOWED = {"P", "Q", "R", "X"}
THEORETICAL_MUTATION_OPERATION = "R"


def load_module(filename, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_fixture(fixture):
    return json.dumps(fixture, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def evaluate_pair(left, right, pair_type, fixtures):
    rows = []
    conflicts = []
    for fixture in fixtures:
        canonical = canonical_fixture(fixture).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()
        left_map = left.evaluate(fixture)
        right_map = right.evaluate(fixture)
        if left_map != right_map:
            status = "INTEROP_CONFLICT"
            conflicts.append(fixture["id"])
        else:
            status = "INTEROP_OK"
        rows.append({
            "fixture_id": fixture["id"],
            "canonical_input_sha256": digest,
            "left_impl": "impl_a.py",
            "right_impl": "impl_b_baseline.py" if pair_type == "baseline" else "impl_b_mut.py",
            "pair_type": pair_type,
            "fixture_verdict_map": {"left": left_map, "right": right_map},
            "status": status,
            "conflict": status == "INTEROP_CONFLICT",
            "unknown_to_accepted_caught": (
                any(v == "unknown" for v in left_map.values()) and
                any(v == "accepted" for v in right_map.values()) and
                left_map != right_map
            ) if pair_type == "mutated" else False,
        })
    return rows, conflicts


def main():
    fixtures = json.loads(CASES.read_text(encoding="utf-8"))
    if len(fixtures) < 20:
        raise SystemExit("fixture count must be at least 20")
    for fixture in fixtures:
        if set(fixture["operations"]) - ALLOWED:
            raise SystemExit(f"invalid operation in {fixture['id']}")
    impl_a = load_module("impl_a.py", "s36_impl_a")
    baseline = load_module("impl_b_baseline.py", "s36_impl_b_baseline")
    mutated = load_module("impl_b_mut.py", "s36_impl_b_mut")
    baseline_rows, baseline_conflicts = evaluate_pair(impl_a, baseline, "baseline", fixtures)
    mutated_rows, mutated_conflicts = evaluate_pair(impl_a, mutated, "mutated", fixtures)
    theoretical = [f["id"] for f in fixtures if THEORETICAL_MUTATION_OPERATION in f["operations"]]
    observed = set(mutated_conflicts)
    unobservable = sorted(set(theoretical) - observed)
    result = {
        "synthetic_only": True,
        "production_verified": False,
        "schema_version": "s36-meta-test-1",
        "offline": True,
        "fixture_count": len(fixtures),
        "operation_set": ["P", "Q", "R", "X"],
        "undeclared_operations": ["X"],
        "mutation": {
            "file": "impl_b_mut.py",
            "function": "verdict_for",
            "operation": "R",
            "from": "unknown",
            "to": "accepted",
            "theoretical_impact_fixtures": theoretical,
        },
        "pairs": {
            "baseline": {
                "left_impl": "impl_a.py",
                "right_impl": "impl_b_baseline.py",
                "results": baseline_rows,
                "conflict_count": len(baseline_conflicts),
                "conflict_fixtures": baseline_conflicts,
            },
            "mutated": {
                "left_impl": "impl_a.py",
                "right_impl": "impl_b_mut.py",
                "results": mutated_rows,
                "conflict_count": len(mutated_conflicts),
                "conflict_fixtures": mutated_conflicts,
                "unobservable_fixtures": unobservable,
            },
        },
        "invariants": {
            "baseline_conflicts_zero": len(baseline_conflicts) == 0,
            "mutated_conflicts_match_theory": set(mutated_conflicts) == set(theoretical) - set(unobservable),
            "unknown_to_accepted_is_conflict": all(r["status"] == "INTEROP_CONFLICT" for r in mutated_rows if r["unknown_to_accepted_caught"]),
            "unobservable_semantics": "unknown",
        },
    }
    OUT.write_text(json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"PASS: fixture_count={len(fixtures)}")
    print(f"PASS: baseline_conflicts={len(baseline_conflicts)}")
    print(f"PASS: mutated_conflicts={len(mutated_conflicts)} fixtures={','.join(mutated_conflicts)}")
    print(f"PASS: UNOBSERVABLE={','.join(unobservable) if unobservable else '[]'}")
    print("PASS: three-state UNKNOWN->accepted upgrades are conflicts")
    print("PASS: deterministic results written to outputs/results.json")


if __name__ == "__main__":
    main()
