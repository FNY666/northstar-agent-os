#!/usr/bin/env python3
"""S23 synthetic-only deterministic local duplicate-record harness.
No network, Gemini CLI, service, credential, or pre-existing research input.
"""
import json, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SYNTHETIC_ONLY = True
PRODUCTION_VERIFIED = False
fixtures = json.loads((ROOT/'fixtures'/'cases.json').read_text())['cases']

def classify(case):
    # Local policy under test: same attempt + same op_id + same record kind.
    # Identical value is accepted idempotently; differing value conflicts.
    # Response/durable reference mismatch is rejected as conflict.
    # A crash/restart/resume does not change UNKNOWN into a terminal result.
    vals = case['records']
    kind = case['kind']
    if kind == 'response_and_durable_mismatch':
        refs = [v.split(':', 1)[1] for v in vals]
        if len(set(refs)) != 1:
            return 'rejected', 'response_durable_reference_mismatch'
        return 'accepted', 'response_durable_reference_consistent'
    if case.get('after_restart') and case.get('prior_status') == 'UNKNOWN':
        return 'UNKNOWN', 'restart_resume_preserves_unknown'
    if len(set(vals)) == 1:
        return 'accepted', 'same_value_duplicate'
    return 'rejected', 'different_value_conflict'

results=[]
for case in fixtures:
    status, reason = classify(case)
    results.append({
        'case_id':case['case_id'], 'status':status, 'reason':reason,
        'synthetic_only':True, 'production_verified':False,
        'worker_count':1, 'op_id':case['op_id'], 'attempt':case['attempt'],
        'kind':case['kind'], 'records':case['records']
    })
out={'synthetic_only':True,'production_verified':False,'scope':'S23 offline single-worker single-op_id same-attempt duplicate records','results':results,
     'statistics':{s:sum(r['status']==s for r in results) for s in ('accepted','rejected','UNKNOWN')}}
(ROOT/'outputs'/'results.json').write_text(json.dumps(out,indent=2,ensure_ascii=False)+'\n')
print(json.dumps(out['statistics'], ensure_ascii=False))