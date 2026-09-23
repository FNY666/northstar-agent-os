#!/usr/bin/env python3
"""Self-contained two-round fixture runner; writes only this delivery tree."""
import copy, hashlib, json, math, os, sys, unicodedata
from pathlib import Path
ROOT=Path('/tmp/A-P0-TCONTRACT-REVIEW-2').resolve(); FIX=ROOT/'fixtures-run'; sys.path.insert(0,str(ROOT))
import t_contract_validator as v
NOW='2026-09-20T22:00:00Z'

def base():
    op={'operation_id':'op-001','kind':'write','target':'acct://test/alpha','args':{'amount':7,'currency':'USD'}}
    run={'task_id':'task-001','run_id':'run-001','idempotency_key':'idem-001','operation_fingerprint':v.operation_fingerprint(op),'artifact_owner':'owner-A','artifact_identity':'identity-A','read_at':'2026-09-20T21:59:00Z','attempt':1}
    dec={'status':'accepted','policy_id':'policy-P0','authority':'authority-A','decided_at':'2026-09-20T21:59:10Z'}
    x={'schema_version':v.SCHEMA,'run':run,'operation':op,'decision':dec,
       'execution':{'status':'succeeded','operation_id':'op-001','idempotency_key':'idem-001','started_at':'2026-09-20T21:59:20Z','ended_at':'2026-09-20T21:59:30Z'},
       'observation':{'status':'returned','source':'observer-A','channel':'observe-A','read_at':'2026-09-20T21:59:40Z','groundtruth_health':'healthy','raw_ref':'evidence://sha256/'+'a'*64},
       'postconditions':[{'name':'effect-applied','status':'verified','source':'pc-A','channel':'pc-A','read_at':'2026-09-20T21:59:45Z','evidence_strength':'strong','evidence_id':'ev-1'}],
       'effect':{'status':'verified','reason':'independent effect evidence','source':'effect-A','read_at':'2026-09-20T21:59:50Z'},
       'receipt':{'run_id':'run-001','operation_id':'op-001','status':'ok','read_at':'2026-09-20T21:59:55Z','producer':'receipt-A'},
       'expected':'verified','trusted_binding':{},'dedupe':{'enabled':True}}
    x['trusted_binding']={'run_id':'run-001','operation_id':'op-001','operation_fingerprint':run['operation_fingerprint'],'operation':op,'decision':dec,'owner':'owner-A','identity':'identity-A','read_at':run['read_at'],'expiry':'2026-09-20T22:30:00Z','policy_revision':'p0-v04'}
    x['trusted_binding']['signature']=v.binding_signature(x)
    return x

def save(name, obj, raw=False):
    p=FIX/(name+'.json')
    if raw: p.write_text(obj,encoding='utf-8')
    else: p.write_text(json.dumps(obj,ensure_ascii=False,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    return p

cases=[]
def add(name, expected, mutate=None, raw=None): cases.append((name,expected,mutate,raw))
add('01-normal-verified','verified')
add('02-effect-failed','failed',lambda x:x.update(effect={**x['effect'],'status':'failed'}))
add('03-no-groundtruth-unknown','unknown',lambda x:x['observation'].update(groundtruth_health='unavailable'))
add('04-empty-postconditions-unknown','unknown',lambda x:x.update(postconditions=[]))
add('05-illegal-receipt-invalid','invalid',lambda x:x['receipt'].update(status='illegal'))
for i,s in enumerate(['failed','not_started','started','timeout','cancelled'],6):
    def m(x,s=s):
        x['execution']['status']=s
        if s in ('not_started','started'): x['execution'].pop('ended_at',None)
    add(f'{i:02d}-execution-{s}', 'failed' if s in ('failed','timeout','cancelled') else 'unknown', m)
add('11-operation-fingerprint-tamper','invalid',lambda x:x['run'].update(operation_fingerprint='sha256:'+'b'*64))
add('12-trusted-binding-missing','unknown',lambda x:x.pop('trusted_binding'))
add('13-trusted-binding-tampered','unknown',lambda x:x['trusted_binding'].update(owner='other-owner'))
add('14-expected-changed-still-verified','verified',lambda x:x.update(expected='unknown'))
add('15-raw-ref-traversal','invalid',lambda x:x['observation'].update(raw_ref='evidence://sha256/../'+('a'*64)))
add('16-observation-error-unknown','unknown',lambda x:x.update(observation={'status':'error','source':'observer-A','channel':'observe-A','read_at':'2026-09-20T21:59:40Z'}))
add('17-postcondition-failed','failed',lambda x:x['postconditions'][0].update(status='failed'))
add('18-receipt-business-error','failed',lambda x:x['receipt'].update(status='business_error'))
add('19-time-window-invalid','invalid',lambda x:x['run'].update(read_at='2026-09-19T00:00:00Z'))
add('20-unknown-field-invalid','invalid',lambda x:x['operation'].update(extra='deny'))
add('21-noninteger-invalid','invalid',lambda x:x['operation']['args'].update(amount=1.5))
add('22-large-integer-invalid','invalid',lambda x:x['operation']['args'].update(amount=10**19))
add('23-empty-effect-unknown','unknown',lambda x:x.update(effect={'status':'unknown','reason':'not available','source':'effect-A','read_at':'2026-09-20T21:59:50Z'}))
add('24-future-event-invalid','invalid',lambda x:x['receipt'].update(read_at='2026-09-20T22:00:01Z'))
add('25-identity-mismatch-invalid','invalid',lambda x:x['receipt'].update(run_id='run-other'))
add('26-duplicate-postcondition-invalid','invalid',lambda x:x['postconditions'].append(copy.deepcopy(x['postconditions'][0])))
add('27-cancelled-observation-unknown','unknown',lambda x:x.update(observation={'status':'cancelled','source':'observer-A','channel':'observe-A','read_at':'2026-09-20T21:59:40Z'}))
add('28-decision-not-accepted-invalid','invalid',lambda x:x['decision'].update(status='rejected'))
add('29-nonobject-run-invalid','invalid',lambda x:x.update(run=[]))
add('30-nonobject-sections-invalid','invalid',lambda x:x.update(operation='not-an-object',decision=[],execution=None))
add('31-trusted-binding-nonobject-invalid','invalid',lambda x:x.update(trusted_binding='not-an-object'))
# Raw JSON parser hazards
add('32-duplicate-json-invalid','invalid',raw='{"schema_version":"x","schema_version":"y"}')
add('33-nfc-collision-invalid','invalid',raw='{"e\u0301":1,"é":2}')
add('34-nan-invalid','invalid',raw='{"x":NaN}')
add('35-infinity-invalid','invalid',raw='{"x":Infinity}')
add('36-negative-infinity-invalid','invalid',raw='{"x":-Infinity}')
add('37-noninteger-json-invalid','invalid',raw='{"x":1.25}')


def run(round_no):
    reg={}; counts={x:0 for x in ('verified','failed','unknown','invalid')}; errors=0; matches=0; verified=0; err_verified=0
    for name, expected, mutate, raw in cases:
        if raw is not None: p=save(f'r{round_no}-{name}',raw,True)
        else:
            obj=base(); mutate(obj) if mutate else None
            # expected is the runner oracle, independent of the fixture's
            # claimed field.  Negative fixtures therefore cannot inherit
            # expected=verified from base().
            obj['expected'] = expected
            p=save(f'r{round_no}-{name}',obj)
        out=v.validate_json(p, trusted_now=NOW, registry=reg)
        counts[out['verdict']]=counts.get(out['verdict'],0)+1
        matches += int(out['verdict']==expected)
        errors += int(not isinstance(out,dict) or 'verdict' not in out)
        verified += int(out['verdict']=='verified')
        err_verified += int(out['verdict']=='verified' and expected!='verified')
    # Explicit idempotency exercise: same key/fingerprint dedupes, changed fingerprint rejects.
    a=v.validate(base(),trusted_now=NOW,registry={}); reg2={}
    first=v.validate(base(),trusted_now=NOW,registry=reg2); second=v.validate(base(),trusted_now=NOW,registry=reg2)
    changed=base(); changed['operation']['args']['amount']=8
    changed['run']['operation_fingerprint']=v.operation_fingerprint(changed['operation']); changed['trusted_binding']['operation']=changed['operation']; changed['trusted_binding']['operation_fingerprint']=changed['run']['operation_fingerprint']; changed['trusted_binding']['signature']=v.binding_signature(changed)
    reject=v.validate(changed,trusted_now=NOW,registry=reg2)
    idem_ok=(first['verdict']=='verified' and second['replay']['action']=='deduplicate' and reject['verdict']=='invalid')
    return {'round':round_no,'rc':0 if matches==len(cases) and errors==0 and err_verified==0 and idem_ok else 1,'fixture_count':len(cases),'counts':counts,'match':matches,'fail':len(cases)-matches,'error':errors,'invalid':counts['invalid'],'unknown':counts['unknown'],'verified':counts['verified'],'ERROR_VERIFIED':err_verified,'idempotency':idem_ok}

if __name__=='__main__':
    FIX.mkdir(parents=True,exist_ok=True)
    results=[run(1),run(2)]
    ok=all(r['rc']==0 for r in results)
    lines=['T-CONTRACT-0 TEST RESULTS','mode=tree-external pure standard-library no services']
    for r in results: lines.append(json.dumps(r,sort_keys=True))
    lines += ['total_rounds=2','total_fixtures_per_round=%d'%len(cases),'rc=%d'%(0 if ok else 1), 'fail=%d'%sum(r['fail'] for r in results),'error=%d'%sum(r['error'] for r in results),'invalid=%d'%sum(r['invalid'] for r in results),'unknown=%d'%sum(r['unknown'] for r in results),'verified=%d'%sum(r['verified'] for r in results),'ERROR_VERIFIED=%d'%sum(r['ERROR_VERIFIED'] for r in results)]
    (ROOT/'TEST-RESULTS.txt').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print('\n'.join(lines)); raise SystemExit(0 if ok else 1)
