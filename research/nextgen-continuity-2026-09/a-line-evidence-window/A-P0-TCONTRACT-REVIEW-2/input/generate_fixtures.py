#!/usr/bin/env python3
import copy, json, sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE)); import t_contract_validator as v
FIX=HERE/'fixtures'; NOW='2026-09-20T22:00:00Z'
def base():
 op={'operation_id':'op-001','kind':'write','target':'acct://test/alpha','args':{'amount':7,'currency':'USD'}}
 fp=v.operation_fingerprint(op)
 return {'schema_version':v.SCHEMA,'run':{'task_id':'task-001','run_id':'run-001','idempotency_key':'idem-001','operation_fingerprint':fp,'artifact_owner':'owner-A','artifact_identity':'identity-A','read_at':'2026-09-20T21:59:00Z','attempt':1},'operation':op,'decision':{'status':'accepted','policy_id':'policy-P0','authority':'authority-A','decided_at':'2026-09-20T21:59:10Z'},'execution':{'status':'succeeded','operation_id':'op-001','idempotency_key':'idem-001','started_at':'2026-09-20T21:59:20Z','ended_at':'2026-09-20T21:59:30Z'},'observation':{'status':'returned','source':'observer-A','channel':'observe-A','read_at':'2026-09-20T21:59:40Z','groundtruth_health':'healthy','raw_ref':'evidence://sha256/'+'a'*64},'postconditions':[{'name':'effect-applied','status':'verified','source':'pc-A','channel':'pc-A','read_at':'2026-09-20T21:59:45Z','evidence_strength':'strong','evidence_id':'ev-1'}],'effect':{'status':'verified','reason':'independent effect evidence','source':'effect-A','read_at':'2026-09-20T21:59:50Z'},'receipt':{'run_id':'run-001','operation_id':'op-001','status':'ok','read_at':'2026-09-20T21:59:55Z','producer':'receipt-A'},'expected':'verified','trusted_binding':{'run_id':'run-001','operation_id':'op-001','operation_fingerprint':fp,'operation':copy.deepcopy(op),'decision':{'status':'accepted','policy_id':'policy-P0','authority':'authority-A','decided_at':'2026-09-20T21:59:10Z'},'owner':'owner-A','identity':'identity-A','read_at':'2026-09-20T21:59:00Z','expiry':'2026-09-20T22:30:00Z','policy_revision':'prototype-only','signature':'offline-declaration'},'dedupe':{'enabled':False}}
def add(name, mutate, expected=None):
 x=copy.deepcopy(b); mutate(x); x['expected']=expected or ('invalid' if name.startswith(('invalid','bad','duplicate','nfc','unknown','raw','future','reverse','missing','binding')) else 'unknown'); cases.append((name,x))
FIX.mkdir(exist_ok=True); cases=[]; b=base(); cases.append(('baseline-verified',b))
add('failed-execution',lambda x:x['execution'].update(status='failed'), 'failed')
add('unknown-started',lambda x:x['execution'].update(status='started',ended_at=None),'unknown')
add('unknown-observation',lambda x:x['observation'].update(status='missing',groundtruth_health=None,raw_ref=None),'unknown')
add('invalid-effect-receipt-conflict',lambda x:(x['effect'].update(status='failed'),x['receipt'].update(status='ok')),'invalid')
add('invalid-verified-receipt-conflict',lambda x:(x['effect'].update(status='verified'),x['receipt'].update(status='rejected')),'invalid')
add('missing-binding',lambda x:x.pop('trusted_binding'))
add('bad-binding-signature',lambda x:x['trusted_binding'].update(signature=''))
add('bad-binding-identity',lambda x:x['trusted_binding'].update(owner='other'))
add('future-end',lambda x:x['execution'].update(ended_at='2099-01-01T00:00:00Z'))
add('future-effect',lambda x:x['effect'].update(read_at='2099-01-01T00:00:00Z'))
add('future-receipt',lambda x:x['receipt'].update(read_at='2099-01-01T00:00:00Z'))
add('reverse-time',lambda x:x['execution'].update(started_at='2026-09-20T21:58:00Z'))
add('old-run',lambda x:x['run'].update(read_at='2026-09-20T00:00:00Z'))
add('missing-postconditions',lambda x:x.update(postconditions=[]))
add('bad-raw-relative',lambda x:x['observation'].update(raw_ref='../../secret'))
add('bad-raw-absolute',lambda x:x['observation'].update(raw_ref='/etc/passwd'))
add('unknown-top-field',lambda x:x.update(unexpected='x'))
add('unknown-run-field',lambda x:x['run'].update(unexpected='x'))
add('unknown-operation-field',lambda x:x['operation'].update(unexpected='x'))
add('bad-operation-target',lambda x:x['operation'].update(target='evil'))
add('bad-fingerprint',lambda x:x['run'].update(operation_fingerprint='sha256:'+'0'*64))
add('bad-attempt',lambda x:x['run'].update(attempt=0))
add('bad-decision',lambda x:x['decision'].update(status='rejected'))
add('bad-receipt-id',lambda x:x['receipt'].update(run_id='other'))
add('bad-observation-source',lambda x:x['observation'].update(source='attacker'))
add('bad-postcondition-status',lambda x:x['postconditions'][0].update(status='invalid'))
add('duplicate-postcondition',lambda x:x['postconditions'].append(copy.deepcopy(x['postconditions'][0])))
add('bad-time',lambda x:x['effect'].update(read_at='not-time'))
add('bad-number',lambda x:x['operation']['args'].update(amount=7.5))
add('huge-number',lambda x:x['operation']['args'].update(amount=10**100))
add('nfc-programmatic',lambda x:x['operation']['args'].update(**{'e\u0301':1,'é':2}))
add('failed-postcondition',lambda x:x['postconditions'][0].update(status='failed'),'failed')
add('unknown-postcondition',lambda x:x['postconditions'][0].update(status='unknown'),'unknown')
add('failed-receipt',lambda x:x['receipt'].update(status='business_error'),'failed')
add('expected-does-not-change-verdict',lambda x:x.update(expected='failed'),'failed')
for name,obj in cases: (FIX/(name+'.json')).write_text(json.dumps(obj,ensure_ascii=False,sort_keys=True,indent=2)+'\n',encoding='utf8')
# JSON text fixtures exercise parser-only defects.
texts={'duplicate-json-top':'{"x":1,"x":2}','duplicate-json-nested':'{"a":{"x":1,"x":2}}','nfc-json-top':'{"e\\u0301":1,"é":2}','nfc-json-nested':'{"a":{"e\\u0301":1,"é":2}}','nan-json':'{"x":NaN}','infinity-json':'{"x":Infinity}','malformed-json':'{"x":','top-list':'[]'}
for name,text in texts.items(): (FIX/(name+'.json.txt')).write_text(text,encoding='utf8')
print(json.dumps({'fixtures':len(cases)+len(texts),'structured':len(cases),'text':len(texts)},sort_keys=True))
