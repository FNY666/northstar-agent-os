#!/usr/bin/env python3
"""Local S22 result/fixture gate; no network access."""
import json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
STATES={"RECOVERED","UNKNOWN","REJECT"}
CLASSES={"NO_EVENT","DELAYED","DROPPED","EXPORTER_FAILURE","QUERY_GAP","RETENTION_EXPIRED","VERIFIED_CONTINUITY","UNKNOWN"}
def main():
    try:
        f=json.loads((ROOT/'fixtures/cases.json').read_text())
        r=json.loads((ROOT/'outputs/results.json').read_text())
    except Exception as e:
        print('FAIL: unreadable local JSON:',e); return 1
    cases=f.get('cases',[]); results=r.get('results',[])
    if not r.get('synthetic_only') or r.get('production_verified') is not False: print('FAIL: provenance gate'); return 1
    if len(cases)!=len(results) or r.get('case_count')!=len(cases): print('FAIL: count mismatch'); return 1
    ids={c.get('id') for c in cases}
    if len(ids)!=len(cases) or {x.get('id') for x in results}!=ids: print('FAIL: IDs mismatch'); return 1
    for x in results:
        if x.get('state') not in STATES: print('FAIL: invalid state'); return 1
        if not x.get('classifications') or not set(x['classifications']) <= CLASSES: print('FAIL: invalid classification'); return 1
        if x['state']=='RECOVERED' and x['classifications'] != ['VERIFIED_CONTINUITY']: print('FAIL: recovered not verified'); return 1
        if x['state']!='RECOVERED' and 'VERIFIED_CONTINUITY' in x['classifications']: print('FAIL: unsafe continuity'); return 1
    counts={s:sum(x['state']==s for x in results) for s in STATES}
    if r.get('state_counts')!=dict(sorted(counts.items())): print('FAIL: state counts'); return 1
    if not {'RECOVERED','UNKNOWN','REJECT'} <= set(counts): print('FAIL: missing state dimension'); return 1
    print(f"PASS: local validator cases={len(cases)} states={dict(sorted(counts.items()))}")
    return 0
if __name__=='__main__': raise SystemExit(main())
