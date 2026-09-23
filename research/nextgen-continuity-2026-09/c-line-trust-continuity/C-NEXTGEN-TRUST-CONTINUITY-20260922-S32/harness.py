#!/usr/bin/env python3
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent

FIELDS=('same_identity','identity_conflict','digest_equivalent','digest_conflict','canonicalization_complete','same_canonicalization','same_algorithm','migration_attested','page_chain_complete','cursor_boundary_closed','watermark_closed','retention_window_closed','within_retention','retention_boundary_attested','fence_valid','fence_conflict')

def digest(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['digest_conflict'] or f['fence_conflict'] or not f['fence_valid']:
        return 'REJECT'
    if (not f['same_identity'] or not f['digest_equivalent'] or not f['canonicalization_complete'] or
        (not f['same_canonicalization'] and not f['migration_attested']) or
        (not f['same_algorithm'] and not f['migration_attested']) or
        not f['page_chain_complete'] or not f['cursor_boundary_closed'] or not f['watermark_closed'] or
        not f['retention_window_closed'] or not f['within_retention'] or not f['retention_boundary_attested']):
        return 'UNKNOWN'
    return 'RECOVERED'

def run():
    data=json.loads((ROOT/'fixtures/cases.json').read_text())
    rows=[]
    for c in data['cases']:
        got=classify(c['flags'])
        rows.append({'id':c['id'],'status':got,'expected':c['status'],'match':got==c['status'],'evidence_count':len(c['evidence'])})
    counts={s:sum(r['status']==s for r in rows) for s in ('RECOVERED','UNKNOWN','REJECT')}
    sweep=[]
    for n in range(1<<len(FIELDS)):
        f={k:bool(n&(1<<i)) for i,k in enumerate(FIELDS)}
        sweep.append({'mask':n,'status':classify(f)})
    minimized=[]
    for target in ('RECOVERED','UNKNOWN','REJECT'):
        for row in sweep:
            if row['status']==target:
                minimized.append({'target':target,'mask':row['mask'],'bits':[i for i in range(len(FIELDS)) if row['mask']&(1<<i)]})
                break
    result={'schema_version':'S32-results-1','synthetic_only':True,'production_verified':False,'claims_status':'inferred','sources':[], 'identity_domain':data['identity_domain'],'digest_domain':data['digest_domain'],'case_count':len(rows),'results':rows,'status_distribution':counts,'coverage':['DIGEST_CANONICALIZATION','HASH_ALGORITHM_MIGRATION','PAGE_CURSOR','WATERMARK','RETENTION_CUTOFF','FENCE_TOKEN','NO_EVENT','UNKNOWN'],'property_sweep':{'dimensions':len(FIELDS),'combinations':len(sweep),'fields':list(FIELDS),'counts':{s:sum(r['status']==s for r in sweep) for s in ('RECOVERED','UNKNOWN','REJECT')},'single_gate_minimizer':minimized},'all_cases_match':all(r['match'] for r in rows),'digest':digest(rows)}
    (ROOT/'outputs/results.json').write_text(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
    return 0 if result['all_cases_match'] and len(sweep)==(1<<len(FIELDS)) else 1
if __name__=='__main__': sys.exit(run())
