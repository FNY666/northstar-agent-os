#!/usr/bin/env python3
"""Independent read-only probes for the tree-external T-Contract-0 review."""
import copy, importlib.util, json
from pathlib import Path

root = Path('/tmp/A-P0-TCONTRACT-REVIEW-2')
spec = importlib.util.spec_from_file_location('runner', root / 'run_tests.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
v = runner.v

base = runner.base()

def show(label, obj, **kw):
    r = v.validate(copy.deepcopy(obj), trusted_now='2026-09-20T22:00:00Z', **kw)
    print(json.dumps({'case': label, 'verdict': r.get('verdict'), 'match': r.get('match'),
                      'warnings': r.get('warnings'), 'errors': r.get('errors'),
                      'replay': r.get('replay')}, sort_keys=True))

show('baseline-local-test-binding', base)
x = copy.deepcopy(base); x.pop('trusted_binding')
show('binding-absent', x)
x['operation']['args']['amount'] = 8
show('operation-mutated-old-binding', x)
x = copy.deepcopy(base); x['operation']['args']['amount'] = 8
x['run']['operation_fingerprint'] = v.operation_fingerprint(x['operation'])
x['trusted_binding']['operation'] = x['operation']
x['trusted_binding']['operation_fingerprint'] = x['run']['operation_fingerprint']
x['trusted_binding']['signature'] = v.binding_signature(x)
show('operation-mutated-re-signed-local-key', x)
x = copy.deepcopy(base); x['receipt']['producer'] = 'unregistered-producer'
show('unregistered-producer-label', x)
x = copy.deepcopy(base); x['observation']['raw_ref'] = 'evidence://sha256/' + 'f' * 64
show('nonexistent-looking-content-address-only', x)
x = copy.deepcopy(base); x['decision']['authority'] = 'arbitrary-authority'
x['trusted_binding']['decision'] = x['decision']
x['trusted_binding']['signature'] = v.binding_signature(x)
show('arbitrary-authority-re-signed-local-key', x)
reg = {}
show('registry-first', base, registry=reg)
show('registry-replay-same-process', base, registry=reg)
y = copy.deepcopy(base); y['operation']['args']['amount'] = 9
y['run']['operation_fingerprint'] = v.operation_fingerprint(y['operation'])
y['trusted_binding']['operation'] = y['operation']
y['trusted_binding']['operation_fingerprint'] = y['run']['operation_fingerprint']
y['trusted_binding']['signature'] = v.binding_signature(y)
show('registry-conflict-same-process', y, registry=reg)
print(json.dumps({'case': 'registry-storage-type', 'type': type(reg).__name__, 'entries': len(reg)}, sort_keys=True))
print(json.dumps({'case': 'authority-key-type', 'test_only': True,
                  'key_name': 'AUTHORITY_KEY', 'key_bytes': len(v.AUTHORITY_KEY)}, sort_keys=True))
