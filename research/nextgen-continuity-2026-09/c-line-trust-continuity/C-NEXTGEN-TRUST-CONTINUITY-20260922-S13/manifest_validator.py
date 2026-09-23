#!/usr/bin/env python3
import json, sys
from pathlib import Path
p=Path(sys.argv[1] if len(sys.argv)>1 else 'research-manifest.json')
d=json.loads(p.read_text())
required={'schema_version','question','scope','claims','coverage','synthetic_only','production_verified'}
assert required <= d.keys(), sorted(required-set(d))
assert d['synthetic_only'] is True and d['production_verified'] is False
assert isinstance(d['scope'],dict) and d['scope'].get('network_access') is False
assert isinstance(d['coverage'],dict)
for c in d['claims']:
    assert {'id','claim','status','confidence','sources','caveat'} <= c.keys()
    assert c['status']=='inferred', c['id']
    assert c['sources']==[], c['id']
print(f"PASS: local manifest invariants; {len(d['claims'])} inferred claims")
