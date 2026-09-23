#!/usr/bin/env python3
"""Local validator for S20 result semantics."""
import json, pathlib, hashlib, sys

ROOT=pathlib.Path(__file__).resolve().parent
cases=json.loads((ROOT/'fixtures/cases.json').read_text())['cases']
res=json.loads((ROOT/'outputs/results.json').read_text())
assert res['synthetic_only'] is True and res['production_verified'] is False
assert res['fixture_count']==len(cases)==len(res['results'])
by={c['fixture_id']:c for c in cases}
for r in res['results']:
    c=by[r['fixture_id']]
    assert r['status'] in {'RECOVERED','UNKNOWN','REJECT'}
    assert r['status']==c['expected_status']
    assert len(r['canonical_input_sha256'])==64
    canon=json.dumps(c,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
    assert r['canonical_input_sha256']==hashlib.sha256(canon).hexdigest()
    assert 'clock_seq_evidence' in r and 'reason' in r and 'blocking_conditions' in r
    assert isinstance(r['reason'],list) and isinstance(r['blocking_conditions'],list)
assert sum(res['status_counts'].values())==len(cases)
print(f"PASS: local result validator; {len(cases)} fixtures; schema and hashes valid")
print("PASS: mutual-exclusive statuses; expected outcomes match")
