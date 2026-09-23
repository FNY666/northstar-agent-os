#!/usr/bin/env python3
"""Validate local research-manifest structure and S16 coverage declarations."""
import json,sys
from pathlib import Path
BASE=Path(__file__).resolve().parent

def main():
    p=BASE/'research-manifest.json'; d=json.loads(p.read_text())
    required={'schema_version','question','scope','claims','coverage'}
    missing=required-set(d)
    if missing: print('FAIL: missing '+','.join(sorted(missing))); return 1
    if not d['scope'].get('synthetic_only') or d['scope'].get('production_verified') is not False:
        print('FAIL: scope flags'); return 1
    if len(d['claims']) < 3: print('FAIL: insufficient claims'); return 1
    for c in d['claims']:
        for k in ('id','claim','status','confidence','sources','caveat'):
            if k not in c: print('FAIL: claim missing '+k); return 1
        if c['status'] not in {'inferred','confirmed','unknown'}: print('FAIL: invalid claim status'); return 1
        if c['status']=='inferred' and c['sources'] != []: print('FAIL: local inferred claim has sources'); return 1
    cov=d['coverage']
    if cov.get('fixture_count',0)<18 or cov.get('rule_sets') != ['v1','v2']:
        print('FAIL: coverage'); return 1
    print(f"PASS: manifest local scope, {len(d['claims'])} claims, {cov['fixture_count']} fixtures, v1+v2")
    return 0
if __name__=='__main__': sys.exit(main())
