#!/usr/bin/env python3
"""Manifest guard for S24 synthetic-only claims."""
import json, sys
from pathlib import Path
p = Path(__file__).resolve().parent/'research-manifest.json'
try:
 d=json.loads(p.read_text())
 assert d['synthetic_only'] is True and d['production_verified'] is False
 assert d['claims'] and all(c['status']=='inferred' and c['sources']==[] for c in d['claims'])
 assert d['scope']['network_access'] is False
 print(f"PASS: manifest guard; {len(d['claims'])} inferred claims, no sources")
except Exception as e:
 print(f"FAIL: manifest guard: {e}"); sys.exit(1)
