#!/usr/bin/env python3
"""Validate manifest-specific S30 invariants."""
import json, sys
from pathlib import Path
p=Path(sys.argv[1] if len(sys.argv)>1 else Path(__file__).with_name("research-manifest.json"))
d=json.loads(p.read_text(encoding="utf-8"))
assert d.get("synthetic_only") is True
assert d.get("production_verified") is False
assert d.get("sources_policy") == "all claims sources=[]"
assert d.get("claims") and all(c.get("status")=="inferred" and c.get("sources")==[] for c in d["claims"])
assert all(k in d.get("limitations",[]) for k in ["production durability", "exactly-once", "rollback", "real external effects", "production readiness"])
print(f"PASS manifest validator: {len(d['claims'])} inferred claims; synthetic-only boundaries valid")
