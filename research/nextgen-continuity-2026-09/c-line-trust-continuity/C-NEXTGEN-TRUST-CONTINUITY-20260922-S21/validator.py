#!/usr/bin/env python3
import json,sys,hashlib
from pathlib import Path

def canon(o): return json.dumps(o,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def main():
 d=json.loads(Path('fixtures/cases.json').read_text()); r=json.loads(Path('outputs/results.json').read_text())
 assert d['synthetic_only'] and not d['production_verified'] and r['synthetic_only'] and not r['production_verified']
 assert len(d['cases'])>=18 and len(r['results'])==len(d['cases'])
 by={x['case_id']:x for x in r['results']}
 for c in d['cases']:
  x=by[c['case_id']]; assert x['judgment']==c['expected']['judgment'],(c['case_id'],x['judgment'],c['expected']['judgment'])
  assert x['nodes']==[n['id'] for n in c['nodes']] and x['edges']==c['edges']
  assert len(x['canonical_input_sha256'])==64
  assert x['canonical_input_sha256']==hashlib.sha256(canon({k:v for k,v in c.items() if k!='expected'})).hexdigest()
  assert x['judgment'] in ('RECOVERED','UNKNOWN','REJECT')
  if x['judgment']=='RECOVERED': assert x['subclass'] in ('direct_edge','transitive_order') and x['inference_path']
  else: assert x['subclass'] is None
 assert sum(x['judgment']=='RECOVERED' for x in r['results'])==7
 assert sum(x['judgment']=='UNKNOWN' for x in r['results'])==12
 assert sum(x['judgment']=='REJECT' for x in r['results'])==5
 print('PASS: local semantic validator; 24 expected judgments match')
 print('PASS: three-state exclusivity and evidence fields validated')
 print('PASS: direct_edge/transitive_order subclasses validated')
 return 0
if __name__=='__main__':sys.exit(main())
