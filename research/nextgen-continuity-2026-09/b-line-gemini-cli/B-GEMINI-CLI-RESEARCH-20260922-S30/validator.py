#!/usr/bin/env python3
"""S30 output validator: synthetic invariants and expected fixture results."""
# synthetic_only=true; production_verified=false
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
cases = json.loads((root / "fixtures/cases.json").read_text())
results = json.loads((root / "outputs/results.json").read_text())
assert cases["synthetic_only"] is True and cases["production_verified"] is False
assert results["synthetic_only"] is True and results["production_verified"] is False
assert results["worker_id"] == "worker-0" and results["op_id"] == "op-s30-single"
assert len(cases["cases"]) >= 14 and len(results["results"]) == len(cases["cases"])
assert all(r["pass"] and r["actual"] == r["expected"] for r in results["results"])
assert all(r["actual"] in {"accepted", "rejected", "UNKNOWN"} for r in results["results"])
assert any(r["actual"] == "UNKNOWN" for r in results["results"])
# Explicit safety invariants represented by fixtures.
byid = {r["id"]: r["actual"] for r in results["results"]}
assert byid["S30-06"] == "rejected" and byid["S30-07"] == "accepted"
assert byid["S30-08"] == "UNKNOWN" and byid["S30-12"] == "UNKNOWN"
print(f"VALIDATOR_PASS: {len(results['results'])} results; UNKNOWN distinct from rejected; late conflict and evidence gates hold")
