#!/usr/bin/env python3
import hashlib,hmac,json,sys
from pathlib import Path

KEY=b'S17-FIXED-NONREAL-HMAC-KEY-v1'
STATUS={'RECOVERED','UNKNOWN','REJECT'}
def canon_a(x): return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def canon_b(x, divergent=False): return json.dumps(x,ensure_ascii=False,sort_keys=not divergent,separators=(',',': ' if divergent else ':')) .encode()
def sha(b): return hashlib.sha256(b).hexdigest()
def expected_sig(policy): return hmac.new(KEY,canon_a(policy),hashlib.sha256).hexdigest()
def rev_hash(rev): return sha(canon_a(rev)) if rev is not None else None
def list_valid(rev):
    if rev is None or not isinstance(rev,dict) or rev.get('unavailable'): return False
    if not isinstance(rev.get('entries'),list) or 'declared_sha256' not in rev: return False
    core={'version':rev.get('version'),'entries':rev['entries']}
    if rev['declared_sha256'] != sha(canon_a(core)): return False
    for e in rev['entries']:
        if not isinstance(e,dict) or 'package_id' not in e or 'revoked_at' not in e: return False
    return True
def in_effect(e, obs):
    return e['revoked_at'] <= obs and (not e.get('effective_until') or obs <= e['effective_until'])
def evaluate(c):
    pol=c['policy']; sig=c.get('signature'); cp=canon_a(pol)
    signature_ok=isinstance(sig,str) and hmac.compare_digest(sig,expected_sig(pol))
    rv=c.get('revocation_list'); rv_ok=list_valid(rv)
    package_id=pol.get('package_id') if isinstance(pol,dict) else None
    hit=bool(rv_ok and any(e.get('package_id')==package_id and in_effect(e,c['observation_time']) for e in rv['entries']))
    divergent=c.get('canonicalization_profile')=='divergent'
    impl_a=sha(canon_a(pol)); impl_b=sha(canon_b(pol,divergent))
    if not signature_ok: status='REJECT'; reason='policy HMAC-SHA256 verification failed'
    elif hit: status='REJECT'; reason='revocation record hit at observation boundary'
    elif not rv_ok: status='UNKNOWN'; reason='revocation list missing, inaccessible, malformed, or integrity unverifiable'
    elif divergent and impl_a != impl_b:
        status='REJECT' if c.get('declared_contradiction') else 'UNKNOWN'
        reason='explicit canonicalization contradiction' if c.get('declared_contradiction') else 'canonicalizer A/B hash divergence; conservative non-rejection'
    elif c.get('implementation_b_available') is False:
        status='UNKNOWN'; reason='canonicalizer B unavailable; no majority-vote or retry escalation'
    else: status='RECOVERED'; reason='signature, revocation integrity, and cross-implementation canonicalization checks passed'
    return {'id':c['id'],'name':c['name'],'status':status,'expected_status':c['expected']['status'],'pass':status==c['expected']['status'],'reason':reason,'blocking_condition':None if status=='RECOVERED' else reason,'provenance':{'implementation_a':'canonicalizer-A/json-sort-keys-v1','implementation_b':'canonicalizer-B/json-sort-keys-v1-or-deliberate-divergence','signature_sha256':sha(sig.encode()) if isinstance(sig,str) else None,'revocation_sha256':rev_hash(rv),'canonical_input_sha256':sha(cp),'canonicalizer_a_sha256':impl_a,'canonicalizer_b_sha256':impl_b,'hmac_key_id':'S17-fixed-nonreal-key-v1'},'synthetic_only':True,'production_verified':False}
def main():
    root=Path(__file__).parent; data=json.loads((root/'fixtures/cases.json').read_text())
    results=[evaluate(c) for c in data['cases']]
    if not all(r['pass'] for r in results):
        for r in results:
            if not r['pass']: print('FAIL',r['id'],r['status'],r['expected_status'])
        return 1
    out={'schema_version':'S17-results-v1','synthetic_only':True,'production_verified':False,'fixture_count':len(results),'run_count':1,'status_counts':{s:sum(r['status']==s for r in results) for s in ('RECOVERED','UNKNOWN','REJECT')},'results':results}
    (root/'outputs').mkdir(exist_ok=True); (root/'outputs/results.json').write_text(json.dumps(out,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
    print(f"PASS fixtures={len(results)} RECOVERED={out['status_counts']['RECOVERED']} UNKNOWN={out['status_counts']['UNKNOWN']} REJECT={out['status_counts']['REJECT']}")
    print('PASS all fixture expectations')
    for r in results: print(f"OK {r['id']} {r['status']}")
    return 0
if __name__=='__main__': raise SystemExit(main())
