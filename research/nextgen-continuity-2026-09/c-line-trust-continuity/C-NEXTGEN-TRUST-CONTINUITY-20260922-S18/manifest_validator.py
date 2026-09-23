#!/usr/bin/env python3
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def main():
 p=ROOT/'research-manifest.json'; d=json.loads(p.read_text())
 req={'schema_version','question','scope','claims','coverage'}; assert req<=d.keys()
 assert d['scope']['network_access']==False and d['scope']['synthetic_only']==True and d['scope']['production_verified']==False
 assert len(d['claims'])>=1
 ids=set()
 for c in d['claims']:
  assert set(('id','claim','status','confidence','sources','caveat'))<=c.keys(); assert c['id'] not in ids; ids.add(c['id'])
  assert c['status']=='inferred'; assert c['sources'] and all(s['url'].startswith('https://') for s in c['sources'])
  assert 'local' in c['caveat'].lower() or 'synthetic' in c['caveat'].lower()
 print(f'PASS: S18 manifest local policy; {len(d["claims"])} inferred claims; no network scope')
if __name__=='__main__': main()
