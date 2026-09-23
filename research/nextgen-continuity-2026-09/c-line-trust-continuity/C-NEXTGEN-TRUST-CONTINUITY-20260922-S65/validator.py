#!/usr/bin/env python3
import json
from pathlib import Path
p = Path(__file__).resolve().parent
r = json.loads((p / 'outputs' / 'results.json').read_text())
assert r['synthetic_only'] is True and r['production_verified'] is False
assert r['claims_status'] == 'inferred' and r['sources'] == []
assert r['case_count'] >= 20 and r['all_cases_match']
assert r['property_sweep']['dimensions'] == 25
assert r['property_sweep']['combinations'] == 33554432
assert sum(r['property_sweep']['counts'].values()) == 33554432
assert set(r['status_distribution']) == {'RECOVERED', 'UNKNOWN', 'REJECT'}
assert len(r['property_sweep']['single_gate_minimizer']) == 3
print('PASS: validator cases=%d sweep=33554432 mutually-exclusive=RECOVERED/UNKNOWN/REJECT' % r['case_count'])
