#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','role_declared','writer_scope_bound',
    'reader_scope_bound','evaluator_scope_bound','handoff_card_complete','state_snapshot_bound',
    'artifact_index_complete','ledger_entry_bound','source_digest_bound','task_boundary_bound',
    'cross_session_message_bound','ack_required_known','ack_received','freeze_before_write',
    'single_writer_attested','independent_evaluator_attested','shared_path_canonical',
    'merge_policy_known','conflict_policy_known','handoff_state_readback','collaboration_conflict',
    'unknown_shared_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['collaboration_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['role_declared'] or not f['writer_scope_bound'] or
        not f['reader_scope_bound'] or not f['evaluator_scope_bound'] or
        not f['handoff_card_complete'] or not f['state_snapshot_bound'] or
        not f['artifact_index_complete'] or not f['ledger_entry_bound'] or
        not f['source_digest_bound'] or not f['task_boundary_bound'] or
        not f['cross_session_message_bound'] or not f['ack_required_known'] or
        not f['ack_received'] or not f['freeze_before_write'] or
        not f['single_writer_attested'] or not f['independent_evaluator_attested'] or
        not f['shared_path_canonical'] or not f['merge_policy_known'] or
        not f['conflict_policy_known'] or not f['handoff_state_readback'] or
        f['unknown_shared_state']):
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
    collaboration_conflict_bit = 1 << FIELDS.index('collaboration_conflict')
    unknown_shared_state_bit = 1 << FIELDS.index('unknown_shared_state')
    required_names = [
        'same_identity','role_declared','writer_scope_bound','reader_scope_bound','evaluator_scope_bound',
        'handoff_card_complete','state_snapshot_bound','artifact_index_complete','ledger_entry_bound',
        'source_digest_bound','task_boundary_bound','cross_session_message_bound','ack_required_known',
        'ack_received','freeze_before_write','single_writer_attested','independent_evaluator_attested',
        'shared_path_canonical','merge_policy_known','conflict_policy_known','handoff_state_readback'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | collaboration_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_shared_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S55-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['WRITER', 'READER', 'EVALUATOR', 'HANDOFF', 'STATE_SNAPSHOT', 'ARTIFACT_INDEX', 'LEDGER', 'SOURCE_DIGEST', 'ACK', 'FREEZE', 'SINGLE_WRITER', 'MERGE', 'CONFLICT', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
