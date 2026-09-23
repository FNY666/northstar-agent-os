#!/usr/bin/env python3
"""Validate S15 research-manifest shape and synthetic-only policy."""
import json,sys
from pathlib import Path

def main():
 p=Path(__file__).resolve().parent/'research-manifest.json'; d=json.loads(p.read_text())
 assert d['schema_version']=='1.0' and d['scope']['synthetic_only'] is True and d['scope']['production_verified'] is False
 assert isinstance(d['claims'],list) and d['claims']
 ids=[]
 for c in d['claims']:
  assert all(k in c for k in ('id','claim','status','confidence','sources','caveat'))
  assert c['id'] not in ids; ids.append(c['id'])
  assert c['status']=='inferred' and c['sources']==[]
  assert 'inferred' in c['caveat'].lower()
 print(f'PASS: manifest local policy; {len(ids)} inferred claims; no external sources')
if __name__=='__main__':
 try: main()
 except (AssertionError,KeyError,TypeError,ValueError) as e: print('ERROR:',e); raise SystemExit(1)
