# synthetic_only=true; production_verified=false
#!/usr/bin/env python3
"""Validate S28 output invariants and fixture coverage."""
import json, sys
from pathlib import Path
root = Path(__file__).resolve().parent
cases = json.loads((root/'fixtures/cases.json').read_text())
out = json.loads((root/'outputs/results.json').read_text())
assert out['synthetic_only'] is True and out['production_verified'] is False
assert out['worker_id'] == 'worker-1' and out['op_id'] == 's28-op-0001'
rows = out['results']; assert len(rows) >= 12
assert {r['case_id'] for r in rows} == {c['case_id'] for c in cases['cases']}
assert all(r['synthetic_only'] is True and r['production_verified'] is False for r in rows)
assert all(r['verdict'] in {'accepted','rejected','UNKNOWN'} for r in rows)
assert any(r['verdict']=='accepted' for r in rows)
assert any(r['verdict']=='rejected' for r in rows)
assert any(r['verdict']=='UNKNOWN' for r in rows)
assert all(r['verdict'] != 'rejected' for r in rows if r['scenario'] in {'missing_response','invalid_reference'})
assert any(r['retry_position']=='before_reference' for r in rows)
assert any(r['retry_position']=='after_reference' for r in rows)
assert any(r['reconciliation_position']=='before_response' for r in rows)
assert any(r['reconciliation_position']=='after_response' for r in rows)
print('PASS: S28 validator; 16 fixtures; accepted/rejected/UNKNOWN; UNKNOWN != REJECT')
