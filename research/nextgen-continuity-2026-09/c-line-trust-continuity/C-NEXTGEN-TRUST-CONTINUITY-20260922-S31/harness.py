#!/usr/bin/env python3
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def digest(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['payload_conflict'] or f['fence_conflict'] or (not f['same_identity'] and f['cross_partition']):
        return 'REJECT'
    if f['query_gap'] or not f['within_retention'] or not f['ordering_complete'] or not f['same_digest'] or not f['same_identity']:
        return 'UNKNOWN'
    return 'RECOVERED'

def run():
    data=json.loads((ROOT/'fixtures/cases.json').read_text())
    out=[]
    for c in data['cases']:
        got=classify(c['flags'])
        out.append({'id':c['id'],'status':got,'expected':c['status'],'match':got==c['status'],'evidence_count':len(c['evidence'])})
    counts={x:sum(r['status']==x for r in out) for x in ('RECOVERED','UNKNOWN','REJECT')}
    sweep=[]
    for n in range(256):
        f={k:bool(n&(1<<i)) for i,k in enumerate(('same_identity','same_digest','cross_partition','ordering_complete','within_retention','query_gap','payload_conflict','fence_conflict'))}
        sweep.append({'mask':n,'status':classify(f)})
    minimized=[]
    for target in ('RECOVERED','UNKNOWN','REJECT'):
        for row in sweep:
            if row['status']==target:
                minimized.append({'target':target,'mask':row['mask'],'bits':[i for i in range(8) if row['mask']&(1<<i)]}); break
    result={'schema_version':'S31-results-1','synthetic_only':True,'production_verified':False,'claims_status':'inferred','sources':[],'identity_domain':data['identity_domain'],'case_count':len(out),'results':out,'status_distribution':counts,'coverage':['NO_EVENT','DELAYED','DROPPED','EXPORTER_FAILURE','QUERY_GAP','PAGINATION_INSUFFICIENT','RETENTION_EXPIRED','VERIFIED_CONTINUITY','UNKNOWN','same payload','conflicting payload','version migration','epoch fence','cross tenant/source'],'property_sweep':{'dimensions':8,'combinations':256,'counts':{s:sum(r['status']==s for r in sweep) for s in ('RECOVERED','UNKNOWN','REJECT')},'single_gate_minimizer':minimized},'all_cases_match':all(r['match'] for r in out),'digest':digest(out)}
    (ROOT/'outputs/results.json').write_text(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
    return 0 if result['all_cases_match'] and sum(result['property_sweep']['counts'].values())==256 else 1
if __name__=='__main__': sys.exit(run())
