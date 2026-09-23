#!/usr/bin/env python3
import json,sys
from pathlib import Path
root=Path(__file__).parent
m=json.loads((root/'research-manifest.json').read_text())
for k in ('schema_version','question','scope','claims','coverage'): assert k in m
assert all(c['status']=='inferred' for c in m['claims'])
assert m['scope']['network_access']==False and m['scope']['synthetic_only']==True
print(f'PASS manifest_validator claims={len(m["claims"])} synthetic_only=true production_verified=false')
