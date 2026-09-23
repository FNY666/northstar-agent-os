#!/usr/bin/env python3
import json,sys
from pathlib import Path
root=Path(__file__).parent
x=json.loads((root/'fixtures/cases.json').read_text())
assert x['synthetic_only'] is True and x['production_verified'] is False
assert len(x['cases'])>=18 and len({c['id'] for c in x['cases']})==len(x['cases'])
for c in x['cases']:
 assert c['synthetic_only'] is True and c['production_verified'] is False
 assert c['expected']['status'] in {'RECOVERED','UNKNOWN','REJECT'}
print(f'PASS validator fixtures={len(x["cases"])} statuses=RECOVERED|UNKNOWN|REJECT')
