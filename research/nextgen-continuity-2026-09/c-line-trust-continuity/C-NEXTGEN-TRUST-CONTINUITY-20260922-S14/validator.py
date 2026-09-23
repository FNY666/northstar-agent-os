#!/usr/bin/env python3
# synthetic_only=true; production_verified=false
import json,sys,pathlib
p=pathlib.Path(__file__).resolve().parent
r=json.loads((p/'outputs/results.json').read_text())
assert r['synthetic_only'] is True and r['production_verified'] is False
assert r['all_pass'] is True and r['case_count']>=14
for x in r['results']:
 assert x['state'] in {'RECOVERED','UNKNOWN','REJECT'}
 assert x['pass'] is True
 assert len(x['provenance']['transitions'])>=1
# Explicit regression guards: conservative UNKNOWN cannot silently upgrade.
for cid in ['S14-01-clock-drift','S14-02-same-event-different-seq','S14-03-duplicate-event-id','S14-04-budget-cut-before-proof','S14-05-budget-cut-at-proof','S14-06-mislabelled-independence','S14-11-clock-drift-with-two-sources','S14-14-seq-gap-only','S14-15-budget-with-explicit-completeness']:
 x=next(y for y in r['results'] if y['case_id']==cid); assert x['state']=='UNKNOWN', cid
for cid in ['S14-09-explicit-verifiable-contradiction','S14-13-contradiction-with-recovery']:
 x=next(y for y in r['results'] if y['case_id']==cid); assert x['state']=='REJECT', cid
for cid in ['S14-08-valid-independent-recovery','S14-12-duplicate-around-valid-proof']:
 x=next(y for y in r['results'] if y['case_id']==cid); assert x['state']=='RECOVERED', cid
print('PASS: local S14 validator; states mutually exclusive; conservative guards hold')
