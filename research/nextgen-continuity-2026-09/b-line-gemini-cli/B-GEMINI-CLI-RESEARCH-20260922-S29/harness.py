#!/usr/bin/env python3
"""S29 synthetic-only deterministic duplicate-delivery harness."""
import hashlib, json, pathlib
ROOT = pathlib.Path(__file__).resolve().parent
cases = json.loads((ROOT/'fixtures/cases.json').read_text())['cases']

def fingerprint(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',',':')).encode()).hexdigest()

def classify(case):
    applied = None
    seen_event = {}
    reasons=[]
    for i, d in enumerate(case['deliveries'], 1):
        if not d['evidence_accessible'] or not d['payload_accessible'] or d['payload'] is None:
            reasons.append(f'delivery {i}: evidence or payload inaccessible; outcome cannot be proven yet')
            if applied is not None:
                return 'UNKNOWN', reasons
            # An unobservable first attempt is non-authoritative; a later
            # observable delivery may still establish the local result.
            continue
        fp = fingerprint(d['payload'])
        eid = d['event_id']
        if eid in seen_event:
            if seen_event[eid] == fp:
                reasons.append(f'delivery {i}: same event and same payload; duplicate accepted')
                continue
            reasons.append(f'delivery {i}: same event with different payload; conflict rejected')
            return 'rejected', reasons
        if applied is None:
            applied = fp
            seen_event[eid] = fp
            reasons.append(f'delivery {i}: first observable payload accepted as local canonical')
        elif fp == applied:
            seen_event[eid] = fp
            reasons.append(f'delivery {i}: equivalent payload; duplicate/retry accepted')
        else:
            reasons.append(f'delivery {i}: payload differs from local canonical; conflict rejected')
            return 'rejected', reasons
    return ('accepted' if applied is not None else 'UNKNOWN'), reasons

results=[]
for c in cases:
    actual, reasons=classify(c)
    results.append({'id':c['id'],'expected_classification':c['expected_classification'],'classification':actual,'match':actual==c['expected_classification'],'reasons':reasons,'synthetic_only':True,'production_verified':False})
out={'synthetic_only':True,'production_verified':False,'worker_id':'worker-s29-1','operation_id':'op-s29-001','model_rule':'local deterministic payload-fingerprint rule; not external/Gemini behavior','results':results}
(ROOT/'outputs').mkdir(exist_ok=True)
(ROOT/'outputs/results.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'cases':len(results),'accepted':sum(x['classification']=='accepted' for x in results),'rejected':sum(x['classification']=='rejected' for x in results),'UNKNOWN':sum(x['classification']=='UNKNOWN' for x in results),'matches':sum(x['match'] for x in results),'all_match':all(x['match'] for x in results),'synthetic_only':True,'production_verified':False},sort_keys=True))
if not all(x['match'] for x in results): raise SystemExit(1)
