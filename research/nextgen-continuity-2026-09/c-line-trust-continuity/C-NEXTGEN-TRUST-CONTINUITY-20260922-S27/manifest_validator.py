#!/usr/bin/env python3
"""Validate manifest contract specific to synthetic-only S27."""
import json,sys
from pathlib import Path
p=json.loads(Path(sys.argv[1] if len(sys.argv)>1 else 'research-manifest.json').read_text())
assert p['synthetic_only'] is True and p['production_verified'] is False
assert p['scope']['network_access'] is False
assert p['scope']['production_inputs'] is False
assert all(c['status']=='inferred' and c['sources']==[] for c in p['claims'])
assert set(p['coverage']['classifications']) >= {'NO_EVENT','DELAYED','DROPPED','EXPORTER_FAILURE','QUERY_GAP','RETENTION_EXPIRED','VERIFIED_CONTINUITY','UNKNOWN'}
print('PASS: S27 manifest-specific invariants')
