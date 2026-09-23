#!/usr/bin/env python3
"""Manifest shape and synthetic provenance validator."""
import json, sys
from pathlib import Path
p = Path(__file__).resolve().parent / "research-manifest.json"
try:
    d = json.loads(p.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"FAIL: manifest JSON: {exc}"); raise SystemExit(1)
required = {"schema_version", "question", "scope", "claims", "coverage", "synthetic_only", "production_verified"}
missing = required - d.keys()
if missing: print("FAIL: missing " + ",".join(sorted(missing))); raise SystemExit(1)
if d["synthetic_only"] is not True or d["production_verified"] is not False: print("FAIL: provenance flags"); raise SystemExit(1)
if not isinstance(d["claims"], list) or not d["claims"]: print("FAIL: claims"); raise SystemExit(1)
for c in d["claims"]:
    if c.get("status") != "inferred" or c.get("sources") != []: print("FAIL: claims must be inferred with sources=[]"); raise SystemExit(1)
print(f"PASS: manifest shape; {len(d['claims'])} inferred claims; synthetic_only=true; production_verified=false")
