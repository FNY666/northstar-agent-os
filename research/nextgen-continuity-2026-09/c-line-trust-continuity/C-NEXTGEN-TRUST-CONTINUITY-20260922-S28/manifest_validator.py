#!/usr/bin/env python3
"""Validate manifest's synthetic-only claims and required coverage."""
import json,sys
from pathlib import Path

def main():
 p=Path(__file__).resolve().parent/'research-manifest.json'; d=json.loads(p.read_text())
 assert d['synthetic_only'] is True and d['production_verified'] is False
 assert all(c['status']=='inferred' and c['sources']==[] for c in d['claims'])
 required={'NO_EVENT','DELAYED','DROPPED','EXPORTER_FAILURE','QUERY_GAP','RETENTION_EXPIRED','VERIFIED_CONTINUITY','UNKNOWN'}
 assert required.issubset(set(d['coverage']['classification_labels']))
 print('PASS: manifest synthetic-only validator')
if __name__=='__main__':
 try: main()
 except (AssertionError,KeyError,TypeError,json.JSONDecodeError) as e: print('FAIL:',e); sys.exit(1)
