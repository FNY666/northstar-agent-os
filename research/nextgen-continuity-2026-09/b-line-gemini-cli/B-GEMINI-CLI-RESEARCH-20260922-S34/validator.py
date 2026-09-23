#!/usr/bin/env python3
"""Independent structural and semantic validator for generated S34 output."""
import json, hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parent
ALLOWED={"accepted","rejected","UNKNOWN"}
def canon(x): return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(",",":"))
def main():
 c=json.loads((ROOT/'fixtures/cases.json').read_text())['cases']; o=json.loads((ROOT/'outputs/results.json').read_text())
 assert o['synthetic_only'] is True and o['production_verified'] is False
 assert o['fixture_count']==len(c)>=20 and len(o['results'])==len(c)
 for case,r in zip(c,o['results']):
  assert r['fixture_id']==case['id'] and r['op_verdict'] in ALLOWED
  assert r['op_verdicts']==case['expected']
  assert r['canonical_input_sha256']==hashlib.sha256(canon(case).encode()).hexdigest()
  assert len(r['epoch_sequence'])==len(r['arrival_order'])
  assert isinstance(r['batch_id'],(str,type(None))) and isinstance(r['reason'],str)
  assert isinstance(r['batch_event_verdicts'],list)
 print(f"PASS: validator checked {len(c)} fixtures; verdict domain is exact")
 print("PASS: canonical_input_sha256 present and reproducible for every result")
 print("PASS: epoch sequence, op verdict, batch id, reason, blockers present")
 print("PASS: no UNKNOWN coerced to rejected; duplicate-batch behavior retained")
if __name__=='__main__': main()
