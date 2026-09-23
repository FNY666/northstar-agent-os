#!/usr/bin/env python3
import hashlib,json,sys
from pathlib import Path

def main():
 p=Path(__file__).resolve().parent; m=json.loads((p/'research-manifest.json').read_text()); errs=[]
 for k in ('schema_version','question','scope','claims','coverage'):
  if k not in m: errs.append('missing:'+k)
 if not isinstance(m.get('claims'),list) or not m['claims']: errs.append('claims_not_nonempty')
 ids=set()
 for i,c in enumerate(m.get('claims',[])):
  for k in ('id','claim','status','confidence','sources','caveat'):
   if k not in c: errs.append(f'claim{i}:missing:{k}')
  if c.get('status')!='inferred': errs.append(f"claim{i}:not_inferred")
  if c.get('id') in ids: errs.append(f"duplicate:{c.get('id')}")
  ids.add(c.get('id'))
  if not c.get('sources'): errs.append(f'claim{i}:no_sources')
  for s in c.get('sources',[]):
   if s.get('tier')!='primary' or not str(s.get('url','')).startswith('https://'): errs.append(f'claim{i}:bad_source')
 if m.get('scope',{}).get('network_access') is not False: errs.append('network_scope_not_false')
 if errs: print('FAIL: '+'; '.join(errs)); return 1
 print(f"PASS: {len(m['claims'])} claims; local inferred-manifest policy valid")
 return 0
if __name__=='__main__': sys.exit(main())
