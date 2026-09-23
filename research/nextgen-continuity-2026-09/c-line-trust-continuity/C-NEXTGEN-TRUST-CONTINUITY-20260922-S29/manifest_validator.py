#!/usr/bin/env python3
import json,sys
from pathlib import Path
p=Path(sys.argv[1] if len(sys.argv)>1 else 'research-manifest.json')
d=json.loads(p.read_text())
assert d['synthetic_only'] is True and d['production_verified'] is False
assert isinstance(d['claims'],list) and d['claims']
assert all(c['status']=='inferred' and c['sources']==[] for c in d['claims'])
print('PASS: manifest synthetic-only flags and inferred/no-source claims verified')
