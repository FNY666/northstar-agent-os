#!/usr/bin/env python3
import hashlib,json,sys
from pathlib import Path

def canon(x): return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def main():
    p=Path(__file__).resolve().parent; fx=json.loads((p/'fixtures/cases.json').read_text()); out=json.loads((p/'outputs/results.json').read_text())
    assert fx['synthetic_only'] is True and fx['production_verified'] is False
    assert out['synthetic_only'] is True and out['production_verified'] is False
    cases=fx['cases']; results=out['results']; assert len(cases)>=20 and len(results)==len(cases)
    assert {c['chain_id'] for c in cases[0]['chains']}=={'L1','L2','L3'}
    allowed={'RECOVERED','UNKNOWN','REJECT'}; assert all(r['status'] in allowed for r in results)
    assert len({r['status'] for r in results})==3
    for c,r in zip(cases,results):
        assert r['event_id']==c['event_id'] and r['case_id']==c['case_id']
        assert r['canonical_input_sha256']==hashlib.sha256(canon(c)).hexdigest()
        assert isinstance(r['chains_checked'],list) and isinstance(r['blocking_conditions'],list)
        assert set(r['chains_with_event']).issubset(set(r['chains_checked']))
    by={r['case_id']:r for r in results}
    assert by['F01']['status']=='RECOVERED'
    for x in ['F03','F04','F06','F07','F09','F10','F11','F15','F16','F17','F19','F21','F22','F24']: assert by[x]['status']=='UNKNOWN'
    for x in ['F05','F14','F20']: assert by[x]['status']=='REJECT'
    assert 'duplicate_hash:L1' in by['F11']['blocking_conditions']
    assert any('inaccessible:L3'==x for x in by['F08']['blocking_conditions'])
    assert 'timeline_ownership' in by['F07']['blocking_conditions']
    print(f"PASS: {len(cases)} fixtures; output shape, hashes, tri-state rules, and required scenarios valid")
if __name__=='__main__':
    try: main()
    except (AssertionError,KeyError,TypeError) as e: print(f'FAIL: {e}'); sys.exit(1)
