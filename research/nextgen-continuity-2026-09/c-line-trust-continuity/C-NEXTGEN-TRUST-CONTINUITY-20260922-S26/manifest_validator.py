#!/usr/bin/env python3
import json,sys
from pathlib import Path
p=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).resolve().parent/'research-manifest.json'
d=json.loads(p.read_text())
assert d['synthetic_only'] is True and d['production_verified'] is False
assert d['claims'] and all(c['status']=='inferred' and c['sources']==[] for c in d['claims'])
required=['NO_EVENT','DELAYED','DROPPED','EXPORTER_FAILURE','QUERY_GAP','RETENTION_EXPIRED','VERIFIED_CONTINUITY','UNKNOWN']
assert all(x in d['coverage']['labels'] for x in required)
assert set(d['coverage']['states'])=={'RECOVERED','UNKNOWN','REJECT'}
print('PASS: manifest validator; synthetic flags, inferred-only claims, empty sources, required labels, states')
