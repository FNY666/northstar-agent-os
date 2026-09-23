#!/usr/bin/env python3
"""Local S16 invariant validator; reads only this slice's outputs and fixtures."""
import json, sys
from pathlib import Path
BASE=Path(__file__).resolve().parent
errors=[]
def err(m): errors.append(m)
def main():
    cases=json.loads((BASE/'fixtures/cases.json').read_text())
    out=json.loads((BASE/'outputs/results.json').read_text())
    if len(cases)<18: err('fewer than 18 fixtures')
    if out.get('fixture_count') != len(cases): err('fixture_count mismatch')
    if out.get('run_count') != len(cases)*2: err('run_count mismatch')
    allowed={'RECOVERED','UNKNOWN','REJECT'}
    ids={c['id'] for c in cases}
    got={r['fixture_id'] for r in out['results']}
    if ids != got: err('fixture ids mismatch')
    for r in out['results']:
        if len(r.get('runs',[])) != 2: err(f"{r['fixture_id']}: not two runs")
        for run in r['runs']:
            if run['rule_set'] not in ('v1','v2'): err(f"{r['fixture_id']}: invalid rule set")
            if run['status'] not in allowed: err(f"{r['fixture_id']}: invalid status")
            for key in ('provenance','reason','blockers','input_hash','synthetic_only','production_verified'):
                if key not in run: err(f"{r['fixture_id']}: run missing {key}")
            if run['synthetic_only'] is not True or run['production_verified'] is not False: err(f"{r['fixture_id']}: provenance flags")
            if not run['input_hash'].startswith('sha256:'): err(f"{r['fixture_id']}: input hash")
        d=r['version_drift']
        if not d.get('recorded'): err(f"{r['fixture_id']}: drift not recorded")
        if d['present'] and r['final_status'] not in ('UNKNOWN','REJECT'): err(f"{r['fixture_id']}: drift not conservative")
        if d['present'] and d['classification']!='VERSION_CONFLICT': err(f"{r['fixture_id']}: drift classification")
        if not d['present'] and d['classification']!='NONE': err(f"{r['fixture_id']}: false drift")
        if r['final_status'] not in allowed: err(f"{r['fixture_id']}: final invalid")
    if errors:
        print('FAIL:'); print('\n'.join(' - '+e for e in errors)); return 1
    print(f"PASS: {len(cases)} fixtures, {len(cases)*2} runs, statuses mutually exclusive")
    print('PASS: provenance, reasons, blockers, hashes, rule_set, drift, synthetic flags present')
    print('PASS: conservative version-conflict handling verified')
if __name__=='__main__': sys.exit(main())
