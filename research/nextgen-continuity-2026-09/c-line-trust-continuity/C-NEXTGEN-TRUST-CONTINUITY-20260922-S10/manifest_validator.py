#!/usr/bin/env python3
"""Research-manifest validator; offline-only.
synthetic_only=true
production_verified=false
"""
import json, os
ROOT=os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(ROOT,"research-manifest.json"),encoding="utf-8") as f:m=json.load(f)
assert m["synthetic_only"] is True
assert m["production_verified"] is False
assert m["network_access"] is False
assert m["real_services_access"] is False
assert m["credentials_access"] is False
assert m["sdk_access"] is False
assert m["fixture_count"] >= 12
assert set(m["evidence_labels"]) == {"confirmed","inferred","unverified","conflicting","inaccessible"}
assert set(m["decision_labels"]) == {"ACCEPT","REJECT","UNKNOWN"}
assert len(m["forbidden_inputs_read"]) == 0
print("MANIFEST VALIDATOR PASS: offline scope, provenance flags, forbidden-input declaration, and coverage")
