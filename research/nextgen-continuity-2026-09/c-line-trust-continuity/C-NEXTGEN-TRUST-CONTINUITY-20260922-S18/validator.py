#!/usr/bin/env python3
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
ALLOWED={'RECOVERED','UNKNOWN','REJECT'}
def main():
    f=json.loads((ROOT/'fixtures/cases.json').read_text()); o=json.loads((ROOT/'outputs/results.json').read_text())
    assert f['synthetic_only'] and not f['production_verified']
    assert o['synthetic_only'] and not o['production_verified']
    cs={x['case_id']:x for x in f['cases']}; rs=o['results']
    assert len(rs)==len(cs)==20
    assert len({r['case_id'] for r in rs})==len(rs)
    for r in rs:
        assert r['case_id'] in cs and r['chain_id']==cs[r['case_id']]['chain_id']
        assert r['status'] in ALLOWED
        assert isinstance(r['canonical_input_sha256'],str) and len(r['canonical_input_sha256'])==64
        assert r['synthetic_only'] is True and r['production_verified'] is False
        assert isinstance(r['blocking_conditions'],list) and isinstance(r['gap_location'],list)
        assert r['status']==cs[r['case_id']]['expected'],(r['case_id'],r['status'],cs[r['case_id']]['expected'])
    # safety invariant: UNKNOWN never silently escalates; only harness expected labels define fixture oracle.
    print(f"PASS: local results validator; {len(rs)} results; mutually exclusive statuses and fixture expectations valid")
if __name__=='__main__': main()
