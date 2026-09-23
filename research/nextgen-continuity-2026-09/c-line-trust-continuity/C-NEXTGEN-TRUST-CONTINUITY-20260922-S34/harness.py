#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','parent_links_complete','causal_acyclic',
    'causal_order_complete','branch_merge_attested','branch_digest_consistent',
    'sequence_monotonic','reorder_window_closed','replay_window_closed',
    'duplicate_dedup_attested','cross_system_link_attested','source_epoch_continuous',
    'watermark_closed','fence_valid','fence_conflict','causal_cycle_conflict',
    'branch_conflict','replay_gap'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['fence_conflict'] or not f['fence_valid'] or f['causal_cycle_conflict'] or f['branch_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['parent_links_complete'] or not f['causal_acyclic'] or
        not f['causal_order_complete'] or not f['branch_merge_attested'] or
        not f['branch_digest_consistent'] or not f['sequence_monotonic'] or
        not f['reorder_window_closed'] or not f['replay_window_closed'] or
        not f['duplicate_dedup_attested'] or not f['cross_system_link_attested'] or
        not f['source_epoch_continuous'] or not f['watermark_closed'] or f['replay_gap']):
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
        'schema_version': 'S34-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['CAUSAL_PARENT', 'BRANCH_MERGE', 'SEQUENCE', 'REORDER_WINDOW', 'REPLAY_WINDOW', 'CROSS_SYSTEM_LINK', 'WATERMARK', 'FENCE', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
