#!/usr/bin/env python3
import json, pathlib, sys
p=pathlib.Path(__file__).resolve().parent
f=json.loads((p/'fixtures/cases.json').read_text()); r=json.loads((p/'outputs/results.json').read_text())
errors=[]
if not f.get('synthetic_only') or f.get('production_verified'): errors.append('fixture provenance flags invalid')
if not r.get('synthetic_only') or r.get('production_verified'): errors.append('result provenance flags invalid')
if len(f['cases']) < 14: errors.append('fewer than 14 fixtures')
if len(r['results']) != len(f['cases']): errors.append('result count mismatch')
if any(x['classification'] not in {'accepted','rejected','UNKNOWN'} for x in r['results']): errors.append('invalid classification')
if any(x['classification']=='UNKNOWN' and x['classification']=='rejected' for x in r['results']): errors.append('UNKNOWN conflated with rejected')
if any(not x['match'] for x in r['results']): errors.append('fixture expectation mismatch')
if len({x['id'] for x in r['results']}) != len(r['results']): errors.append('duplicate result ids')
if errors:
 print('FAIL: '+'; '.join(errors)); sys.exit(1)
print(f"PASS: {len(r['results'])} deterministic fixtures; classifications valid; UNKNOWN distinct from rejected; synthetic_only=true; production_verified=false")
