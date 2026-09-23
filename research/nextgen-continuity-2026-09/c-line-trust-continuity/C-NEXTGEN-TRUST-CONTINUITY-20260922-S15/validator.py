#!/usr/bin/env python3
"""Local S15 result validator; never contacts a network."""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def canon(v): return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(",",":"))
def sha(v): return hashlib.sha256(canon(v).encode()).hexdigest()
def main():
    cases=json.loads((ROOT/'fixtures/cases.json').read_text())
    data=json.loads((ROOT/'outputs/results.json').read_text())
    assert data['synthetic_only'] is True and data['production_verified'] is False
    assert data['case_count']==len(cases)>=16
    by={c['id']:c for c in cases}; rows=data['results']; assert len(rows)==len(cases)
    allowed={'RECOVERED','UNKNOWN','REJECT'}
    for r in rows:
        assert r['id'] in by and r['status'] in allowed
        assert r['synthetic_only'] is True and r['production_verified'] is False
        assert r['input_hash']==sha(by[r['id']]['input'])
        assert isinstance(r['provenance'],list) and r['reason'] and r['blocker']
    expected_reject={'S15-02-cross-source-mismatch','S15-03-fingerprint-reuse','S15-04-same-summary-heterogeneous','S15-05-replay-inversion','S15-10-explicit-contradiction'}
    got={r['id'] for r in rows if r['status']=='REJECT'}
    assert got==expected_reject, (got,expected_reject)
    assert all(r['status']!='RECOVERED' for r in rows if r['id'] in {'S15-07-clock-over-bound','S15-08-partial-provenance','S15-09-budget-truncation','S15-11-missing-evidence','S15-12-inaccessible','S15-13-ambiguous-linkage','S15-14-majority-vote-trap','S15-15-retry-no-change','S15-17-complete-unverified','S15-18-explicit-negative-not-proven'})
    print('PASS: local result validation; 18 cases, three-state policy and hashes hold')
if __name__=='__main__':
    try: main()
    except (AssertionError,KeyError,TypeError,ValueError) as e: print('ERROR:',e); raise SystemExit(1)
