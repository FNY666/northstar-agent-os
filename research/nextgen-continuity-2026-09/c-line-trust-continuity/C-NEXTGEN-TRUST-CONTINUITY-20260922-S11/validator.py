#!/usr/bin/env python3
# synthetic_only=true; production_verified=false
import json, pathlib, sys
R=pathlib.Path(__file__).resolve().parent
errors=[]
def fail(x): errors.append(x)
for f in ['REPORT.md','sources.md','harness.py','fixtures/cases.json','outputs/results.json','research-manifest.json','SHA256SUMS','validator.py','manifest_validator.py']:
    if not (R/f).is_file(): fail('missing '+f)
for f in ['REPORT.md','sources.md','harness.py','fixtures/cases.json','outputs/results.json','research-manifest.json']:
    if (R/f).is_file():
        s=(R/f).read_text(errors='replace')
        if 'synthetic_only=true' not in s and '"synthetic_only": true' not in s: fail(f+' lacks synthetic_only=true')
        if 'production_verified=false' not in s and '"production_verified": false' not in s: fail(f+' lacks production_verified=false')
try:
 d=json.loads((R/'fixtures/cases.json').read_text())
 if len(d.get('cases',[]))<12: fail('fewer than 12 fixtures')
 ids=[x.get('id') for x in d['cases']]
 if len(ids)!=len(set(ids)): fail('duplicate fixture id')
 classes={'confirmed','inferred','unverified','conflicting','inaccessible'}
 if not classes.issubset({x.get('evidence_class') for x in d['cases']}): fail('missing evidence class')
 o=json.loads((R/'outputs/results.json').read_text())
 if len(o.get('results',[]))!=len(d['cases']): fail('result count mismatch')
 if set(o.get('status_vocabulary',[])) != {'ACCEPT','REJECT','UNKNOWN'}: fail('status vocabulary mismatch')
except Exception as e: fail('json error '+str(e))
if errors:
 print('FAIL')
 print('\n'.join(errors)); sys.exit(1)
print('PASS validator: fixtures, flags, outputs, vocabulary')
