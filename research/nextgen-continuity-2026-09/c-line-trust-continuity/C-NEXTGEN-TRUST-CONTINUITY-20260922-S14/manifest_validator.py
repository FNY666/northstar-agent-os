#!/usr/bin/env python3
# synthetic_only=true; production_verified=false
import json, pathlib
p=pathlib.Path(__file__).resolve().parent
m=json.loads((p/'research-manifest.json').read_text())
assert m['synthetic_only'] is True and m['production_verified'] is False
for k in ['schema_version','question','scope','claims','coverage']: assert k in m
assert m['claims'] and all(set(['id','claim','status','confidence','sources','caveat'])<=set(c) for c in m['claims'])
for c in m['claims']:
 assert c['status']=='inferred'
 assert c['sources']==[]
print('PASS: S14 manifest is synthetic-only and all claims inferred')
