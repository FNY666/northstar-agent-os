#!/usr/bin/env python3
import json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
REQUIRED={"schema_version","question","scope","claims","coverage"}
STATUSES={"confirmed","conflicting","inferred","unverified","inaccessible"}
def main():
 d=json.loads((ROOT/"research-manifest.json").read_text())
 assert REQUIRED <= d.keys()
 assert d["synthetic_only"] is True and d["production_verified"] is False
 assert isinstance(d["claims"],list) and d["claims"]
 ids=set()
 for c in d["claims"]:
  assert {"id","claim","status","confidence","sources","caveat"} <= c.keys()
  assert c["id"] not in ids; ids.add(c["id"])
  assert c["status"] in STATUSES
  if c["status"]=="confirmed": assert c["sources"]
  for s in c["sources"]:
   assert {"url","publisher","published_or_updated","tier","support"} <= s.keys()
 print(f"PASS: local manifest validator; {len(d['claims'])} claims; statuses valid")
if __name__=='__main__': main()
