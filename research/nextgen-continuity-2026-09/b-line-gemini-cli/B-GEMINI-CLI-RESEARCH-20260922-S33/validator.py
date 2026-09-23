#!/usr/bin/env python3
"""Independent offline checks for S33 outputs."""
import hashlib,json,sys
from pathlib import Path
R=Path(__file__).resolve().parent

def canon(o): return json.dumps(o,ensure_ascii=False,sort_keys=True,separators=(",",":"))
def main():
 c=json.loads((R/'fixtures/cases.json').read_text()); o=json.loads((R/'outputs/results.json').read_text())
 assert c['synthetic_only'] and not c['production_verified']
 assert len(c['fixtures'])>=22 and len({x['id'] for x in c['fixtures']})==len(c['fixtures'])
 assert len({len(x['input']['epochs']) for x in c['fixtures']})>0 and max(len(x['input']['epochs']) for x in c['fixtures'])>=4
 assert o['fixture_count']==len(c['fixtures']) and len(o['results'])==len(c['fixtures'])
 allowed={'accepted','rejected','UNKNOWN'}; counts={x:0 for x in allowed}
 for case,res in zip(c['fixtures'],o['results']):
  assert res['fixture_id']==case['id']
  assert res['epoch_sequence']==case['input']['epochs']
  assert res['canonical_input_sha256']==hashlib.sha256(canon(case['input']).encode()).hexdigest()
  assert res['synthetic_only'] and not res['production_verified']
  for j in res['op_judgments']:
   assert j['verdict'] in allowed; counts[j['verdict']]+=1
   assert isinstance(j['reason'],str) and j['reason'] and isinstance(j['blocking_conditions'],list)
 # Required behavior assertions
 by={r['fixture_id']:r for r in o['results']}
 def j(fid,ep,op): return next(x for x in by[fid]['op_judgments'] if x['epoch']==ep and x['op']==op)
 assert j('F02_rollover_missing_old',2,'P')['verdict']=='UNKNOWN'
 assert j('F03_rollover_new_complete',2,'P')['verdict']=='accepted'
 assert j('F04_delayed_ack',2,'Q')['verdict']=='UNKNOWN'
 assert j('F05_missing_ack',1,'R')['verdict']=='UNKNOWN'
 assert j('F06_unknown_X',1,'X')['verdict']=='UNKNOWN' and j('F06_unknown_X',1,'P')['verdict']=='accepted'
 assert j('F08_duplicate_payload',2,'R')['verdict']!='accepted'
 assert j('F09_revoked_epoch',1,'P')['verdict']=='UNKNOWN' and j('F09_revoked_epoch',1,'P')['verdict']!='rejected'
 assert j('F11_reordered_ack',1,'P')['verdict']=='UNKNOWN'
 assert j('F12_stale_event',1,'P')['verdict']=='UNKNOWN'
 print('PASS: schema, hashes, and verdict domain validated')
 print(f"PASS: fixtures={len(c['fixtures'])} verdicts accepted={counts['accepted']} rejected={counts['rejected']} UNKNOWN={counts['UNKNOWN']}")
 print('PASS: required rollover/delayed/missing/unknown/duplicate/revoke invariants validated')
 return 0
if __name__=='__main__': sys.exit(main())
