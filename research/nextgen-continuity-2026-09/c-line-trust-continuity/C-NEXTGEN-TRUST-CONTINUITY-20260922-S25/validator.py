#!/usr/bin/env python3
"""Local invariant validator for the S25 synthetic experiment."""
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ALLOWED = {"RECOVERED", "UNKNOWN", "REJECT"}
LABELS = {"NO_EVENT", "DELAYED", "DROPPED", "EXPORTER_FAILURE", "QUERY_GAP", "RETENTION_EXPIRED", "VERIFIED_CONTINUITY", "UNKNOWN"}

def fail(msg):
    print("FAIL: " + msg)
    raise SystemExit(1)

def main():
    manifest = json.loads((ROOT / "research-manifest.json").read_text())
    fixtures = json.loads((ROOT / "fixtures/cases.json").read_text())
    results = json.loads((ROOT / "outputs/results.json").read_text())
    if manifest.get("synthetic_only") is not True or manifest.get("production_verified") is not False: fail("manifest provenance flags")
    if fixtures.get("synthetic_only") is not True: fail("fixture synthetic_only")
    if results.get("synthetic_only") is not True or results.get("production_verified") is not False: fail("result provenance flags")
    cases = fixtures["cases"]
    rows = results["results"]
    if len(cases) != len(rows): fail("case/result count mismatch")
    if len({c["case_id"] for c in cases}) != len(cases): fail("duplicate case")
    for c, r in zip(cases, rows):
        if c["case_id"] != r["case_id"]: fail("ordering/id mismatch")
        if r["status"] not in ALLOWED: fail("invalid three-state status")
        if c["classification"] not in LABELS: fail("coverage label missing")
        if r["classification"] != c["classification"]: fail("classification mismatch")
        if r["status"] != c["expected_status"]: fail("expected status mismatch")
        if r["status"] == "RECOVERED":
            e = c["evidence"]
            required = [e.get("independent_observers", 0) >= 2, e.get("freshness_seconds", 999) <= 30, e.get("max_clock_skew_seconds", 999) <= 5, e.get("cross_signature_complete") is True, e.get("identity_epoch_fence_continuous") is True, e.get("platform_log_external_closed") is True, e.get("external_effect_confirmed") is True, e.get("platform_log_match") is True]
            if not all(required): fail("RECOVERED without explicit threshold")
    if set(c["classification"] for c in cases) != LABELS: fail("not all required labels covered")
    if set(r["status"] for r in rows) != ALLOWED: fail("not all three states covered")
    print(f"PASS: local invariants; {len(rows)} cases; labels={len(LABELS)}; states=3")

if __name__ == "__main__": main()
