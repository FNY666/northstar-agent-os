#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','slice_id_bound','version_monotonic',
    'state_transition_declared','previous_digest_bound','new_digest_recorded',
    'migration_reason_bound','duplicate_entry_deduped','conflict_entry_detected',
    'canonical_winner_declared','derived_archive_bound','raw_preserved',
    'manifest_recomputed','cross_slice_reference_closed','status_transition_valid',
    'question_unchanged_or_migrated','claim_revision_bound','source_set_closed',
    'filesystem_state_readback','convergence_attested','ledger_conflict',
    'unknown_migration'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['ledger_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['slice_id_bound'] or not f['version_monotonic'] or
        not f['state_transition_declared'] or not f['previous_digest_bound'] or
        not f['new_digest_recorded'] or not f['migration_reason_bound'] or
        not f['duplicate_entry_deduped'] or not f['conflict_entry_detected'] or
        not f['canonical_winner_declared'] or not f['derived_archive_bound'] or
        not f['raw_preserved'] or not f['manifest_recomputed'] or
        not f['cross_slice_reference_closed'] or not f['status_transition_valid'] or
        not f['question_unchanged_or_migrated'] or not f['claim_revision_bound'] or
        not f['source_set_closed'] or not f['filesystem_state_readback'] or
        not f['convergence_attested'] or f['unknown_migration']):
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
    identity_conflict_bit = 1 << FIELDS.index('identity_conflict')
    ledger_conflict_bit = 1 << FIELDS.index('ledger_conflict')
    unknown_migration_bit = 1 << FIELDS.index('unknown_migration')
    required_names = [
        'same_identity','slice_id_bound','version_monotonic','state_transition_declared',
        'previous_digest_bound','new_digest_recorded','migration_reason_bound','duplicate_entry_deduped',
        'conflict_entry_detected','canonical_winner_declared','derived_archive_bound','raw_preserved',
        'manifest_recomputed','cross_slice_reference_closed','status_transition_valid',
        'question_unchanged_or_migrated','claim_revision_bound','source_set_closed',
        'filesystem_state_readback','convergence_attested'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | ledger_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_migration_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S57-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['SLICE_ID', 'VERSION', 'STATE_TRANSITION', 'PREVIOUS_DIGEST', 'NEW_DIGEST', 'MIGRATION_REASON', 'DUPLICATE', 'CONFLICT', 'CANONICAL_WINNER', 'DERIVED_ARCHIVE', 'RAW', 'MANIFEST', 'CROSS_SLICE_REFERENCE', 'STATUS_TRANSITION', 'CLAIM_REVISION', 'SOURCE_SET', 'FILESYSTEM_READBACK', 'CONVERGENCE', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
