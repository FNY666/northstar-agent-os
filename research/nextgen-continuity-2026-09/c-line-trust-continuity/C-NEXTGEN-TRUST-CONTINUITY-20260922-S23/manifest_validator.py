#!/usr/bin/env python3
import json, hashlib
from pathlib import Path
R=Path(__file__).resolve().parent
m=json.loads((R/'research-manifest.json').read_text())
assert m['synthetic_only'] is True and m['production_verified'] is False
assert m['claims'] and all(c['status']=='inferred' and c['sources']==[] for c in m['claims'])
expected={'REPORT.md','sources.md','research-manifest.json','SHA256SUMS','harness.py','fixtures/cases.json','outputs/results.json','validator.py','manifest_validator.py'}
assert expected <= set(m['artifacts'])
print('MANIFEST_VALIDATOR_PASS claims=%d artifacts=%d' % (len(m['claims']),len(m['artifacts'])))
