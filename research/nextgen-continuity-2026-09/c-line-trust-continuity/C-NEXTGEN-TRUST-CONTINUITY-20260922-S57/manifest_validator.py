#!/usr/bin/env python3
import json
from pathlib import Path
p = Path(__file__).resolve().parent
m = json.loads((p / 'research-manifest.json').read_text())
assert m['synthetic_only'] is True and m['production_verified'] is False
assert m['claims_status'] == 'inferred' and m['sources'] == []
assert all(c['status'] == 'inferred' and c['sources'] == [] for c in m['claims'])
assert m['coverage']['cases'] >= 20 and m['coverage']['property_sweep'] == 8388608
print('PASS: manifest policy synthetic_only=true production_verified=false sources=[] claims=inferred')
