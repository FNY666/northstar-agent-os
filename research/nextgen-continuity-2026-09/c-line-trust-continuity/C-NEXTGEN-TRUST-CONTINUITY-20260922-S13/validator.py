#!/usr/bin/env python3
import json, sys
from pathlib import Path
p=Path(sys.argv[1] if len(sys.argv)>1 else 'outputs/results.json')
d=json.loads(p.read_text())
assert d.get('synthetic_only') is True and d.get('production_verified') is False
rs=d['results']; assert len(rs)>=14
allowed={'RECOVERED','UNKNOWN','REJECT'}
assert {r['status'] for r in rs} <= allowed
by={r['case_id']:r for r in rs}
for r in rs:
    assert r['synthetic_only'] is True and r['production_verified'] is False
    assert r['reason'] and isinstance(r['provenance'],list)
    for x in r['provenance']:
        for k in ('source_id','event_id','event_time','observed_at','seq','decision','accessible','freshness_age_seconds','input_index','considered','fresh','usable','observation_role'): assert k in x
assert by['S13-01-fresh-corroborated']['status']=='RECOVERED'
assert by['S13-02-single-observation']['status']=='UNKNOWN'
assert by['S13-03-stale-only']['status']=='UNKNOWN'
assert by['S13-04-same-source-duplicate']['status']=='UNKNOWN'
assert by['S13-05-out-of-order']['status']=='RECOVERED'
assert by['S13-06-boundary-fresh']['status']=='RECOVERED'
assert by['S13-07-boundary-stale']['status']=='UNKNOWN'
assert by['S13-08-budget-complete']['status']=='RECOVERED'
assert by['S13-09-budget-exhausted']['status']=='UNKNOWN'
assert by['S13-10-explicit-conflict']['status']=='REJECT'
assert by['S13-11-missing']['status']=='UNKNOWN'
assert by['S13-12-inaccessible']['status']=='UNKNOWN'
assert by['S13-13-mixed-access']['status']=='RECOVERED'
assert by['S13-14-no-clear-conflict']['status']=='RECOVERED'
assert by['S13-15-one-reject-only']['status']=='UNKNOWN'
assert by['S13-16-out-of-order-conflict']['status']=='REJECT'
# Safety invariants: unknown never silently upgrades; reject requires explicit conflict group.
for r in rs:
    if r['status']=='REJECT': assert r['conflict_groups'], r['case_id']
    if r['status']=='RECOVERED': assert r['recovery_groups'], r['case_id']
print(f'PASS: local result invariants; {len(rs)} cases')
