#!/usr/bin/env python3
"""Local semantic validator for S28 outputs and fail-closed invariants."""
import json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def main():
    f=json.loads((ROOT/'fixtures/cases.json').read_text())
    r=json.loads((ROOT/'outputs/results.json').read_text())
    assert len(f)==r['summary']['case_count']
    assert r['synthetic_only'] is True and r['production_verified'] is False
    assert set(r['summary']['status_counts'])=={'RECOVERED','UNKNOWN','REJECT'}
    assert r['property_sweep']['violations']==0
    assert r['minimizer']['found']==8
    by={x['case_id']:x for x in r['cases']}
    assert by['C01-baseline-closed']['status']=='RECOVERED'
    assert by['C09-equivocation-cross-region']['status']=='REJECT'
    assert by['C13-hard-conflict']['status']=='REJECT'
    for x in r['cases']:
        assert x['status'] in ('RECOVERED','UNKNOWN','REJECT')
    print('PASS: local S28 validator')
if __name__=='__main__':
    try: main()
    except (AssertionError, KeyError, json.JSONDecodeError) as e:
        print('FAIL:',e); sys.exit(1)
