#!/usr/bin/env python3
"""Validate S22 research manifest contract."""
import json,sys
from pathlib import Path
p=Path(__file__).resolve().parent/'research-manifest.json'
def main():
 d=json.loads(p.read_text()); errs=[]
 if d.get('synthetic_only') is not True: errs.append('synthetic_only must be true')
 if d.get('production_verified') is not False: errs.append('production_verified must be false')
 if d.get('sources') != []: errs.append('top-level sources must be empty')
 for c in d.get('claims',[]):
  if c.get('status')!='inferred' or c.get('sources')!=[]: errs.append('claim provenance/status violation')
 if errs: print('FAIL: '+'; '.join(errs)); return 1
 print(f"PASS: manifest local contract claims={len(d.get('claims',[]))} synthetic_only=true production_verified=false sources=[]")
 return 0
if __name__=='__main__': raise SystemExit(main())
