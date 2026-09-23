#!/usr/bin/env python3
import json, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
cases=json.loads((ROOT/'fixtures/cases.json').read_text())
results=json.loads((ROOT/'outputs/results.json').read_text())
assert len(cases) >= 20 and len(results['results']) == len(cases)
byid={r['id']:r for r in results['results']}
for c in cases:
    r=byid[c['id']]['decisions']
    assert set(r).issuperset({'P','Q','R'})
    for op in c['ops']:
        assert r[op] in {'accepted','rejected','UNKNOWN'}
    unknown_ids={e['op_id'] for e in c['events'] if e['op_id'] not in c['ops']}
    for op in unknown_ids: assert r[op] == 'UNKNOWN'
# invariants explicitly covered by fixture set
assert byid['F01']['decisions'] == {'P':'accepted','Q':'accepted','R':'accepted'}
assert byid['F04']['decisions']['P'] == 'rejected'  # duplicate evidence
assert byid['F07']['decisions']['Q'] == 'rejected'  # reordered evidence
assert byid['F10']['decisions']['R'] == 'UNKNOWN'   # stale ack epoch
assert byid['F13']['decisions']['P'] == 'UNKNOWN'   # event epoch mismatch
assert byid['F16']['decisions']['X'] == 'UNKNOWN'   # unknown op group
assert byid['F16']['decisions']['P'] == 'accepted'
print(f'VALIDATOR PASS: {len(cases)} fixtures; tri-state and isolation invariants hold')
