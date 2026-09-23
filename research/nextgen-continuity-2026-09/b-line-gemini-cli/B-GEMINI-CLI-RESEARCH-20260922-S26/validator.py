#!/usr/bin/env python3
"""Local result validator only. synthetic_only=true; production_verified=false"""
import json
from pathlib import Path
p=Path(__file__).resolve().parent/'outputs/results.json'
x=json.loads(p.read_text())
assert x['synthetic_only'] is True
assert x['production_verified'] is False
assert x['worker_count']==1
assert x['op_id']=='synthetic-op-S26-0001'
assert x['result_count']==14
assert x['summary']=={'accepted':4,'rejected':4,'UNKNOWN':6}
assert len(x['results'])==14
assert {r['classification'] for r in x['results']}=={'accepted','rejected','UNKNOWN'}
assert all(r['evidence_status'] in {'confirmed','inferred','unverified','conflicting','inaccessible'} for r in x['results'])
print('validator: PASS (14 fixtures; accepted=4 rejected=4 UNKNOWN=6)')
