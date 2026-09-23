#!/usr/bin/env python3
SYNTHETIC_ONLY = True
PRODUCTION_VERIFIED = False
"""Deterministic S35 runner; offline, synthetic-only, single worker."""
import hashlib, importlib.util, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent
CASES = ROOT / "fixtures" / "cases.json"
OUT = ROOT / "outputs" / "results.json"

def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def run():
    cases_doc = json.loads(CASES.read_text())
    cases = cases_doc["fixtures"]
    a, b = load("impl_a"), load("impl_b")
    rows = []
    for fixture in cases:
        va, vb = a.evaluate_fixture(fixture), b.evaluate_fixture(fixture)
        rows.append({
            "fixture_id": fixture["fixture_id"],
            "canonical_input_sha256": hashlib.sha256(canonical(fixture)).hexdigest(),
            "impl_A": {"impl_id":"impl-A", "verdicts":va},
            "impl_B": {"impl_id":"impl-B", "verdicts":vb},
            "consistent": va == vb,
            "conflict": va != vb,
            "interop": "INTEROP_OK" if va == vb else "INTEROP_CONFLICT",
        })
    result = {
        "synthetic_only": True, "production_verified": False,
        "operation_set": ["P", "Q", "R", "X"], "declared_operations": ["P", "Q", "R"],
        "fixture_count": len(cases), "results": rows,
    }
    OUT.write_text(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n")
    ok = sum(r["consistent"] for r in rows)
    conflicts = len(rows) - ok
    print(f"fixtures={len(rows)} impl_A_impl_B_consistent={ok} conflicts={conflicts}")
    return 0

if __name__ == "__main__":
    raise SystemExit(run())
