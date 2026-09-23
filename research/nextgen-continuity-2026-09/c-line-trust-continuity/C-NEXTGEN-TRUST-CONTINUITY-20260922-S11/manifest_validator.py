#!/usr/bin/env python3
# synthetic_only=true; production_verified=false
import json, pathlib, sys
R=pathlib.Path(__file__).resolve().parent
m=json.loads((R/'research-manifest.json').read_text())
required=['schema_version','question','scope','claims','coverage']
missing=[x for x in required if x not in m]
if missing:
 print('FAIL manifest missing: '+', '.join(missing)); sys.exit(1)
if m.get('synthetic_only') is not True or m.get('production_verified') is not False:
 print('FAIL manifest flags'); sys.exit(1)
if not isinstance(m['claims'],list) or not m['claims']: print('FAIL claims'); sys.exit(1)
if not isinstance(m['coverage'],dict): print('FAIL coverage'); sys.exit(1)
print('PASS manifest validator: schema/question/scope/claims/coverage')
