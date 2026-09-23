#!/usr/bin/env python3
import json, itertools, hashlib, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent
CASES=ROOT/'fixtures/cases.json'; OUT=ROOT/'outputs/results.json'
LABELS=['NO_EVENT','DELAYED','DROPPED','EXPORTER_FAILURE','QUERY_GAP','RETENTION_EXPIRED','VERIFIED_CONTINUITY','UNKNOWN']

def decide(c):
    hard = c.get('hard_conflict',False) and (c.get('fence_replay',False) or c['epoch'] < c['prior_epoch'])
    if hard: return 'REJECT'
    recovered = (c['revocation_visible'] and c['ordering_closed'] and c['epoch']==c['prior_epoch'] and c['fence']==c['prior_fence']+1 and c['receipt'] and c['persistent_log'] and c['external_effect'] and c['fresh'] and not c.get('observer_stale',False) and c.get('region_propagated',False) and not c.get('query_gap',False) and not c.get('retention_expired',False) and not c.get('fence_replay',False) and c['classification']=='VERIFIED_CONTINUITY')
    return 'RECOVERED' if recovered else 'UNKNOWN'

def prop(c, s):
    if s=='RECOVERED':
        assert c['classification']=='VERIFIED_CONTINUITY'
        for k in ('revocation_visible','ordering_closed','receipt','persistent_log','external_effect','fresh','region_propagated'):
            assert c.get(k) is True, (c['id'],k)
        assert c['epoch']==c['prior_epoch'] and c['fence']==c['prior_fence']+1
        assert not c.get('observer_stale',False) and not c.get('fence_replay',False)
    if c.get('observer_stale') or not c.get('region_propagated') or not c.get('ordering_closed'):
        assert s!='RECOVERED'

def shrink_counterexample():
    c={'id':'minimal','classification':'DELAYED','revocation_visible':True,'ordering_closed':False,'epoch':1,'prior_epoch':1,'fence':2,'prior_fence':1,'receipt':True,'persistent_log':True,'external_effect':True,'fresh':True,'observer_stale':False,'region_propagated':True}
    assert decide(c)=='UNKNOWN'; return {'events':1,'open_gate':'ordering_closed','state':decide(c)}

def property_sweep():
    counts={}
    keys=['revocation_visible','ordering_closed','receipt','persistent_log','external_effect','fresh','observer_stale','region_propagated']
    n=0
    for bits in itertools.product([False,True], repeat=len(keys)):
        c=dict(zip(keys,bits)); c.update(classification='VERIFIED_CONTINUITY',epoch=1,prior_epoch=1,fence=2,prior_fence=1,id='p')
        s=decide(c); prop(c,s); counts[s]=counts.get(s,0)+1; n+=1
    return {'combinations':n,'states':counts,'all_properties_pass':True}

def main():
    data=json.loads(CASES.read_text()); rows=[]
    for c in data['cases']:
        s=decide(c); prop(c,s); rows.append({'id':c['id'],'label':c['label'],'classification':c['classification'],'state':s})
    out={'schema_version':'s26.results.v1','synthetic_only':True,'production_verified':False,'case_count':len(rows),'results':rows,'state_distribution':{s:sum(x['state']==s for x in rows) for s in ['RECOVERED','UNKNOWN','REJECT']},'coverage_labels':LABELS+['late_receipt_after_revocation','fence_replay','epoch_rollback','cross_region_delay','observer_stale_view','ordering_conflict','external_effect_mismatch','minimal_counterexample','property_based'],'minimal_counterexample':shrink_counterexample(),'property_test':property_sweep()}
    OUT.parent.mkdir(exist_ok=True); OUT.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'case_count':len(rows),'state_distribution':out['state_distribution'],'minimal_counterexample':out['minimal_counterexample'],'property_test':out['property_test']},sort_keys=True))
if __name__=='__main__': main()
