#!/usr/bin/env python3
import json,sys
from pathlib import Path

def main():
 m=json.loads(Path('research-manifest.json').read_text()); assert m['synthetic_only'] is True and m['production_verified'] is False
 assert isinstance(m['claims'],list) and m['claims']
 for c in m['claims']:
  assert all(k in c for k in ('id','claim','status','confidence','sources','caveat'))
  assert c['status']=='inferred' and c['sources']==[]
 r=json.loads(Path('outputs/results.json').read_text()); assert r['fixture_count']==24
 print('PASS: manifest linkage and synthetic-only policy validated')
 print('PASS: claims all status=inferred with empty sources')
 return 0
if __name__=='__main__':sys.exit(main())
