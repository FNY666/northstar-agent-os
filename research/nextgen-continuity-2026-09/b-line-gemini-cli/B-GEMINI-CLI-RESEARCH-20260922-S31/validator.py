#!/usr/bin/env python3
"""S31 output validator; synthetic-only, offline.
synthetic_only=true; production_verified=false
"""
import json, sys
from pathlib import Path
root = Path(__file__).resolve().parent
result = json.loads((root/'outputs/results.json').read_text())
cases = json.loads((root/'fixtures/cases.json').read_text())
assert result['synthetic_only'] is True and result['production_verified'] is False
assert result['worker_count'] == 1 and result['op_ids'] == ['A','B']
assert result['case_count'] == len(cases['cases']) >= 16
assert result['fail_count'] == 0
assert result['pass_count'] == result['case_count']
assert set(result['verdict_counts']) == {'accepted','rejected','UNKNOWN'}
for rec in result['records']:
    assert rec['pass'] is True
    assert rec['actual'] == rec['expected']
    assert set(rec['actual']) == {'A','B'}
    assert all(v in {'accepted','rejected','UNKNOWN'} for v in rec['actual'].values())
print(f"PASS: S31 validator cases={result['case_count']} pass={result['pass_count']} fail={result['fail_count']} verdict_counts={result['verdict_counts']}")
