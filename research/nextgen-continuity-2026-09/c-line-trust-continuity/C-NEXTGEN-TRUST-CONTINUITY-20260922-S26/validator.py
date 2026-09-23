#!/usr/bin/env python3
import json, sys
from pathlib import Path
R=Path(__file__).resolve(); root=R.parent

def die(m): print('FAIL:',m); raise SystemExit(1)
def main():
    m=json.loads((root/'research-manifest.json').read_text()); c=json.loads((root/'fixtures/cases.json').read_text()); o=json.loads((root/'outputs/results.json').read_text())
    if m.get('synthetic_only') is not True or m.get('production_verified') is not False: die('manifest mode flags')
    if any(x.get('status')!='inferred' or x.get('sources')!=[] for x in m['claims']): die('claim evidence policy')
    if o.get('synthetic_only') is not True or o.get('production_verified') is not False: die('output mode flags')
    if o['case_count'] != len(c['cases']) or len(o['results']) != len(c['cases']): die('case count')
    states={x['state'] for x in o['results']}
    if not states <= {'RECOVERED','UNKNOWN','REJECT'}: die('state domain')
    if sum(o['state_distribution'].values()) != len(c['cases']): die('distribution')
    if o['minimal_counterexample']['events'] != 1 or o['minimal_counterexample']['state']=='RECOVERED': die('minimal counterexample')
    if not o['property_test']['all_properties_pass']: die('properties')
    print('PASS: local validator; synthetic-only flags, claims, cases, states, counterexample, properties')
if __name__=='__main__': main()
