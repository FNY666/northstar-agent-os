#!/usr/bin/env python3
"""S10 artifact validator; local-only.
synthetic_only=true
production_verified=false
"""
import json, os, sys
ROOT=os.path.dirname(os.path.abspath(__file__))
required=["REPORT.md","sources.md","research-manifest.json","SHA256SUMS","harness.py","fixtures/cases.json","outputs/results.json"]
for rel in required:
    p=os.path.join(ROOT,rel)
    if not os.path.isfile(p): raise SystemExit(f"MISSING {rel}")

def load(p):
    with open(os.path.join(ROOT,p),encoding="utf-8") as f:return json.load(f)
cases=load("fixtures/cases.json"); results=load("outputs/results.json"); manifest=load("research-manifest.json")
assert cases["synthetic_only"] is True and cases["production_verified"] is False
assert results["synthetic_only"] is True and results["production_verified"] is False
assert manifest["synthetic_only"] is True and manifest["production_verified"] is False
assert len(cases["fixtures"]) >= 12
assert len(results["results"]) == len(cases["fixtures"])
assert {c["evidence_status"] for c in cases["fixtures"]} == {"confirmed","inferred","unverified","conflicting","inaccessible"}
assert {r["fail_closed"] for r in results["results"]} <= {"ACCEPT","REJECT","UNKNOWN"}
assert {r["fail_open"] for r in results["results"]} <= {"ACCEPT","REJECT","UNKNOWN"}
for p in ["REPORT.md","sources.md","harness.py"]:
    text=open(os.path.join(ROOT,p),encoding="utf-8").read()
    assert "synthetic_only=true" in text and "production_verified=false" in text
print("VALIDATOR PASS: required artifacts, flags, fixtures, labels, and result shape")
