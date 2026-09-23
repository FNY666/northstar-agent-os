#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','root_attested','leaf_canonical',
    'inclusion_proof_valid','consistency_proof_valid','checkpoint_chain_complete',
    'root_sequence_monotonic','root_epoch_continuous','observer_quorum_agreed',
    'observer_independent','freshness_closed','key_rotation_attested',
    'algorithm_compatible','fork_conflict','proof_conflict','stale_root_conflict',
    'query_gap','proof_gap'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['fork_conflict'] or f['proof_conflict'] or f['stale_root_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['root_attested'] or not f['leaf_canonical'] or
        not f['inclusion_proof_valid'] or not f['consistency_proof_valid'] or
        not f['checkpoint_chain_complete'] or not f['root_sequence_monotonic'] or
        not f['root_epoch_continuous'] or not f['observer_quorum_agreed'] or
        not f['observer_independent'] or not f['freshness_closed'] or
        not f['key_rotation_attested'] or not f['algorithm_compatible'] or
        f['query_gap'] or f['proof_gap']):
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
        'schema_version': 'S35-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['MERKLE_ROOT', 'INCLUSION_PROOF', 'CONSISTENCY_PROOF', 'CHECKPOINT_CHAIN', 'ROOT_ROTATION', 'OBSERVER_QUORUM', 'FRESHNESS', 'FORK', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
