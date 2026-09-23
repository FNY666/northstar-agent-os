#!/usr/bin/env python3
"""Local validator for S27 result invariants."""
import json, sys
from pathlib import Path
D=Path(__file__).resolve().parent
p=json.loads((D/'outputs/results.json').read_text())
cases=json.loads((D/'fixtures/cases.json').read_text())
assert p['synthetic_only'] is True and p['production_verified'] is False
assert p['case_count']==len(cases)==len(p['results'])
assert {r['status'] for r in p['results']} <= {'RECOVERED','UNKNOWN','REJECT'}
for r in p['results']:
    c=next(x for x in cases if x['case_id']==r['case_id'])
    if r['status']=='RECOVERED':
        assert all(r['checks'].values()), r
    if c.get('hard_conflict'): assert r['status']=='REJECT'
    if not c.get('retention',{}).get('within_boundary',False) or not c.get('query',{}).get('complete',False): assert r['status']!='RECOVERED'
    if 'duplicate_receipt' in c.get('crash_restart',{}).get('events',[]): assert r['status']!='RECOVERED'
    if c.get('watermark',{}).get('revocation_reached') is False: assert r['status']!='RECOVERED'
assert p['property_sweep']['property_pass'] is True
assert p['property_sweep']['combination_count']==256
print('PASS: local result invariants; cases=%d' % len(cases))
