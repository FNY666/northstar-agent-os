#!/usr/bin/env python3
"""Validate S20 research manifest fields beyond the generic checker."""
import json, pathlib
p=pathlib.Path(__file__).resolve().parent/'research-manifest.json'
d=json.loads(p.read_text(encoding='utf-8'))
assert d['scope']['synthetic_only'] is True and d['scope']['production_verified'] is False
assert d['scope']['network_access'] is False
assert d['scope']['real_clock_or_ntp'] is False
assert d['scope']['forbidden_inputs']
for c in d['claims']:
    assert set(('id','claim','status','confidence','sources','caveat')) <= set(c)
    assert c['status']=='inferred'
    assert isinstance(c['sources'],list) and c['sources']
print(f"PASS: manifest validator; {len(d['claims'])} claims are inferred and synthetic-only")
print("PASS: scope forbids network, real clock/NTP, credentials, and external research artifacts")
