#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','root_attested','delegation_chain_complete',
    'signer_scope_valid','key_status_current','revocation_watermark_closed',
    'payload_bound','context_bound','bundle_canonical','transform_chain_attested',
    'redaction_attested','resign_authorized','timestamp_fresh','issuer_epoch_continuous',
    'quorum_agreed','signer_equivocation','scope_conflict','revocation_conflict'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['signer_equivocation'] or f['scope_conflict'] or f['revocation_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['root_attested'] or not f['delegation_chain_complete'] or
        not f['signer_scope_valid'] or not f['key_status_current'] or
        not f['revocation_watermark_closed'] or not f['payload_bound'] or
        not f['context_bound'] or not f['bundle_canonical'] or
        not f['transform_chain_attested'] or not f['redaction_attested'] or
        not f['resign_authorized'] or not f['timestamp_fresh'] or
        not f['issuer_epoch_continuous'] or not f['quorum_agreed']):
        return 'UNKNOWN'
    return 'RECOVERED'

def main():
    data = json.loads((ROOT / 'fixtures' / 'cases.json').read_text())
    rows = []
    for case in data['cases']:
        got = classify(case['flags'])
        rows.append({'id': case['id'], 'status': got, 'expected': case['status'], 'match': got == case['status'], 'evidence_count': len(case['evidence'])})
    counts = {s: sum(r['status'] == s for r in rows) for s in ('RECOVERED', 'UNKNOWN', 'REJECT')}
    combinations = 1 << len(FIELDS)
    sweep_counts = {s: 0 for s in ('RECOVERED', 'UNKNOWN', 'REJECT')}
    minimizers = []
    found = set()
    for mask in range(combinations):
        flags = {name: bool(mask & (1 << i)) for i, name in enumerate(FIELDS)}
        status = classify(flags)
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S36-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['DELEGATION_CHAIN', 'SCOPE', 'KEY_STATUS', 'REVOCATION_WATERMARK', 'PAYLOAD_BINDING', 'CONTEXT_BINDING', 'TRANSFORM', 'REDACTION', 'RESIGN', 'FRESHNESS', 'QUORUM', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
