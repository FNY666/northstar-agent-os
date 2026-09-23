#!/usr/bin/env python3
# synthetic_only=true; production_verified=false
import json, hashlib, pathlib, sys
ROOT=pathlib.Path(__file__).resolve().parent
FLAG={'synthetic_only':True,'production_verified':False}
STATES=['prepared','journaled','acknowledged','replayed','reconciled']

def policy(raw, mode):
    if raw=='ACCEPT': return 'ACCEPT'
    if raw=='REJECT': return 'REJECT'
    return 'REJECT' if mode=='fail-closed' else 'ACCEPT'

def run_case(c, cut=None):
    state='prepared'; transitions=[]; remaining=int(c.get('retry_budget',0)); failures=int(c.get('journal_failures',0)); digest='D0'; raw='UNKNOWN'; reason='not_reconciled'
    for op in c['ops']:
        if op=='journal':
            # Consume retry failures deterministically before the successful attempt.
            while failures>0:
                failures-=1; remaining-=1
                transitions.append({'from':state,'to':state,'event':'journal_attempt_failed','remaining_budget':remaining})
                if remaining<=0:
                    return {'raw':'UNKNOWN','reason':'retry_budget_exhausted','state':state,'transitions':transitions}
            if remaining<=0:
                return {'raw':'UNKNOWN','reason':'retry_budget_exhausted','state':state,'transitions':transitions}
            remaining-=1; old=state; state='journaled'; transitions.append({'from':old,'to':state,'event':'journal','remaining_budget':remaining})
        elif op=='ack_ok':
            old=state; state='acknowledged'; transitions.append({'from':old,'to':state,'event':'ack_match'})
        elif op=='ack_collision':
            transitions.append({'from':state,'to':state,'event':'ack_idempotency_collision'}); return {'raw':'REJECT','reason':'idempotency_key_collision','state':state,'transitions':transitions}
        elif op=='ack_conflict':
            transitions.append({'from':state,'to':state,'event':'ack_conflicting_payload'}); return {'raw':'REJECT','reason':'conflicting_acknowledgement','state':state,'transitions':transitions}
        elif op=='ack_missing':
            transitions.append({'from':state,'to':state,'event':'ack_missing'}); return {'raw':'UNKNOWN','reason':'acknowledgement_unobserved','state':state,'transitions':transitions}
        elif op=='operator_abort':
            transitions.append({'from':state,'to':state,'event':'operator_abort'}); return {'raw':'REJECT','reason':'operator_abort','state':state,'transitions':transitions}
        elif op=='replay':
            old=state; state='replayed'; transitions.append({'from':old,'to':state,'event':'replay'})
        elif op=='replay_duplicate':
            transitions.append({'from':state,'to':state,'event':'duplicate_replay_same_digest'}); reason='duplicate_replay_idempotent'
        elif op=='replay_conflict':
            transitions.append({'from':state,'to':state,'event':'duplicate_replay_conflicting_digest'}); return {'raw':'REJECT','reason':'duplicate_replay_conflict','state':state,'transitions':transitions}
        elif op=='reconcile_stale':
            transitions.append({'from':state,'to':state,'event':'stale_checkpoint'}); return {'raw':'REJECT','reason':'stale_checkpoint','state':state,'transitions':transitions}
        elif op=='reconcile':
            old=state; state='reconciled'; transitions.append({'from':old,'to':state,'event':'reconcile'})
            raw='ACCEPT'; reason=reason if reason!='not_reconciled' else 'consistent_local_trace'
        if cut is not None and len([t for t in transitions if t['from']!=t['to']])==cut:
            return {'raw':'UNKNOWN','reason':'crash_cut_after_transition_'+str(cut),'state':state,'transitions':transitions,'crash_cut':cut}
    return {'raw':raw,'reason':reason,'state':state,'transitions':transitions}

def main():
    data=json.loads((ROOT/'fixtures/cases.json').read_text())
    results=[]
    for c in data['cases']:
        base=run_case(c, c.get('cut_at'))
        cuts=[]
        maxcut=sum(1 for op in c['ops'] if op in ('journal','ack_ok','replay','reconcile'))
        for n in range(1,maxcut+1):
            r=run_case(c,n); cuts.append({'after_transition':n,'raw':r['raw'],'reason':r['reason']})
        results.append({'id':c['id'],'title':c['title'],'evidence_class':c['evidence_class'],'expected_raw':c['expected_raw'],'raw':base['raw'],'reason':base['reason'],'state':base['state'],'transitions':base['transitions'],'crash_cut_results':cuts,'decisions':{'fail-closed':policy(base['raw'],'fail-closed'),'fail-open':policy(base['raw'],'fail-open')}})
    out={'synthetic_only':True,'production_verified':False,'state_order':STATES,'status_vocabulary':['ACCEPT','REJECT','UNKNOWN'],'policy_note':'UNKNOWN is never rewritten in raw results; policy decisions map it only at the boundary.','results':results}
    (ROOT/'outputs').mkdir(exist_ok=True)
    (ROOT/'outputs/results.json').write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'synthetic_only':True,'production_verified':False,'cases':len(results),'output':str(ROOT/'outputs/results.json'),'raw_counts':{s:sum(x['raw']==s for x in results) for s in ('ACCEPT','REJECT','UNKNOWN')}},sort_keys=True))
if __name__=='__main__': main()
