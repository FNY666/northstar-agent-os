#!/usr/bin/env python3
"""Local structural validator for the S30 offline package."""
import json, sys
from pathlib import Path
root = Path(__file__).resolve().parent
required = ["REPORT.md","sources.md","research-manifest.json","SHA256SUMS","harness.py","fixtures/cases.json","outputs/results.json","validator.py","manifest_validator.py"]
missing = [p for p in required if not (root/p).is_file()]
if missing: raise SystemExit("FAIL missing: " + ", ".join(missing))
manifest=json.loads((root/"research-manifest.json").read_text())
if manifest.get("synthetic_only") is not True or manifest.get("production_verified") is not False: raise SystemExit("FAIL boundary flags")
if any(c.get("status") != "inferred" or c.get("sources") != [] for c in manifest.get("claims", [])): raise SystemExit("FAIL claims status/sources")
cases=json.loads((root/"fixtures/cases.json").read_text())["cases"]
results=json.loads((root/"outputs/results.json").read_text())
if len(cases) < 10 or len(results.get("cases",[])) != len(cases): raise SystemExit("FAIL case count/results")
if results.get("property_sweep",{}).get("combinations") != 256: raise SystemExit("FAIL sweep")
if results.get("property_sweep",{}).get("violations") != []: raise SystemExit("FAIL sweep violations")
if not all(x["state"] in {"RECOVERED","UNKNOWN","REJECT"} for x in results["cases"]): raise SystemExit("FAIL state")
print(f"PASS local validator: {len(cases)} cases; 256 sweep; fail-closed states valid")
