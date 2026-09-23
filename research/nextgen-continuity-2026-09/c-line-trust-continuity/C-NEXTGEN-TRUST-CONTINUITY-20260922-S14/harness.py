#!/usr/bin/env python3
"""S14 deterministic synthetic-only provenance state machine; no network or services."""
# synthetic_only=true; production_verified=false
import hashlib, json, pathlib
ROOT=pathlib.Path(__file__).resolve().parent
CASES=ROOT/'fixtures'/'cases.json'; OUT=ROOT/'outputs'/'results.json'
STATES={'RECOVERED','UNKNOWN','REJECT'}

def sha(x): return hashlib.sha256(x.encode()).hexdigest()
def run(case):
    state='UNKNOWN'; reasons=[]; raw=case.get('events',[]); seen={}; dropped=[]
    for idx,e in enumerate(raw):
        eid=e.get('event_id')
        if eid in seen:
            dropped.append({'input_index':idx,'event_id':eid,'reason':'duplicate_event_id_deduplicated','canonical_input_index':seen[eid]})
        else: seen[eid]=idx
    unique=[e for i,e in enumerate(raw) if seen.get(e.get('event_id'))==i]
    reasons.append({'from':'UNKNOWN','to':'UNKNOWN','reason':'initial_state_conservative','evidence':[]})
    contradictions=[e for e in unique if e.get('kind')=='contradiction' and e.get('verifiable') is True and e.get('independence_verified') is True]
    if contradictions:
        state='REJECT'; reasons.append({'from':'UNKNOWN','to':'REJECT','reason':'explicit_verifiable_contradiction','evidence':[e['event_id'] for e in contradictions]})
    else:
        candidates=[e for e in unique if e.get('kind')=='recovery_candidate' and e.get('verifiable') is True and e.get('independence_verified') is True]
        sources={e.get('source_id') for e in candidates}
        blockers=[]
        if case.get('budget_truncated') is True: blockers.append('budget_truncated_without_explicit_completeness_proof')
        if any(e.get('clock_anomaly') is True for e in candidates): blockers.append('clock_anomaly_not_normalized')
        seqs=[e.get('seq') for e in candidates if isinstance(e.get('seq'),int)]
        if len(seqs)>1 and seqs != list(range(min(seqs),max(seqs)+1)): blockers.append('sequence_gap_or_noncontiguous_order')
        if len(candidates)<2: blockers.append('fewer_than_two_verified_recovery_candidates')
        if len(sources)<2: blockers.append('fewer_than_two_independent_source_ids')
        if blockers:
            reasons.append({'from':'UNKNOWN','to':'UNKNOWN','reason':'recovery_not_authorized;_conservative_hold','evidence':[e.get('event_id') for e in candidates],'blockers':blockers})
        else:
            state='RECOVERED'; reasons.append({'from':'UNKNOWN','to':'RECOVERED','reason':'two_or_more_verified_candidates; distinct_sources; contiguous_seq; no_clock_anomaly; complete_stream','evidence':[e['event_id'] for e in candidates]})
    # Mutually exclusive invariant is enforced here, not inferred from expected label.
    assert state in STATES and len([s for s in STATES if s==state])==1
    return {'case_id':case['id'],'synthetic_only':True,'production_verified':False,'state':state,'expected_state':case['expected_state'],'pass':state==case['expected_state'],'input_sha256':sha(json.dumps(case,sort_keys=True,separators=(',',':'))),'provenance':{'model':'S14-local-deterministic-v1','event_count_raw':len(raw),'event_count_unique':len(unique),'canonical_event_ids':[e.get('event_id') for e in unique],'deduplicated':dropped,'transitions':reasons,'limitations':['no remote state','no durability','no exactly-once','no rollback','no production readiness']}}

def main():
    data=json.loads(CASES.read_text()); results=[run(c) for c in data['cases']]
    payload={'synthetic_only':True,'production_verified':False,'model':'S14-local-deterministic-v1','case_count':len(results),'all_pass':all(r['pass'] for r in results),'results':results}
    OUT.write_text(json.dumps(payload,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({'case_count':len(results),'all_pass':payload['all_pass'],'output':str(OUT)}))
if __name__=='__main__': main()
