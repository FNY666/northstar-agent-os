#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','checkpoint_attested','snapshot_digest_match',
    'delta_chain_complete','compaction_manifest_complete','archive_restore_attested',
    'restore_generation_match','tombstone_chain_complete','segment_chain_complete',
    'watermark_closed','retention_window_closed','source_epoch_continuous','fence_valid',
    'fence_conflict','digest_conflict','restore_ambiguous','gap_present',
    'restore_generation_conflict'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['fence_conflict'] or not f['fence_valid'] or f['digest_conflict'] or f['restore_generation_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['checkpoint_attested'] or not f['snapshot_digest_match'] or
        not f['delta_chain_complete'] or not f['compaction_manifest_complete'] or
        not f['archive_restore_attested'] or not f['restore_generation_match'] or
        not f['tombstone_chain_complete'] or not f['segment_chain_complete'] or
        not f['watermark_closed'] or not f['retention_window_closed'] or
        not f['source_epoch_continuous'] or f['restore_ambiguous'] or f['gap_present']):
        return 'UNKNOWN'
    return 'RECOVERED'

def main():
    data = json.loads((ROOT / 'fixtures' / 'cases.json').read_text())
    rows = []
    for case in data['cases']:
        got = classify(case['flags'])
        rows.append({'id': case['id'], 'status': got, 'expected': case['status'], 'match': got == case['status'], 'evidence_count': len(case['evidence'])})
    counts = {s: sum(r['status'] == s for r in rows) for s in ('RECOVERED', 'UNKNOWN', 'REJECT')}
    sweep_counts = {s: 0 for s in ('RECOVERED', 'UNKNOWN', 'REJECT')}
    minimizers = []
    found = set()
    combinations = 1 << len(FIELDS)
    for mask in range(combinations):
        flags = {name: bool(mask & (1 << i)) for i, name in enumerate(FIELDS)}
        status = classify(flags)
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S33-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['CHECKPOINT', 'SNAPSHOT', 'DELTA_CHAIN', 'COMPACTION', 'ARCHIVE_RESTORE', 'TOMBSTONE', 'WATERMARK', 'RETENTION', 'FENCE', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {
            'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS,
            'counts': sweep_counts,
            'single_gate_minimizer': minimizers
        }
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
