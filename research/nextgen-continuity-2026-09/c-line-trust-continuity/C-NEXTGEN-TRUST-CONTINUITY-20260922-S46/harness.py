#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','protocol_declared','initialize_complete',
    'session_id_bound','new_session_attested','load_session_attested','prompt_bound',
    'cancel_request_attested','cancel_state_observed','notification_sequence_closed',
    'tool_call_permission_bound','context_update_bound','diff_open_close_bound',
    'accepted_rejected_bound','stdin_transport_closed','session_persistence_attested',
    'reconnect_state_reconciled','unknown_remote_effect_absent','duplicate_notification_deduped',
    'lifecycle_conflict','unknown_session_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['lifecycle_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['protocol_declared'] or not f['initialize_complete'] or
        not f['session_id_bound'] or not f['new_session_attested'] or not f['load_session_attested'] or
        not f['prompt_bound'] or not f['cancel_request_attested'] or not f['cancel_state_observed'] or
        not f['notification_sequence_closed'] or not f['tool_call_permission_bound'] or
        not f['context_update_bound'] or not f['diff_open_close_bound'] or
        not f['accepted_rejected_bound'] or not f['stdin_transport_closed'] or
        not f['session_persistence_attested'] or not f['reconnect_state_reconciled'] or
        not f['unknown_remote_effect_absent'] or not f['duplicate_notification_deduped'] or
        f['unknown_session_state']):
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
    lifecycle_conflict_bit = 1 << FIELDS.index('lifecycle_conflict')
    unknown_session_state_bit = 1 << FIELDS.index('unknown_session_state')
    required_names = [
        'same_identity','protocol_declared','initialize_complete','session_id_bound',
        'new_session_attested','load_session_attested','prompt_bound','cancel_request_attested',
        'cancel_state_observed','notification_sequence_closed','tool_call_permission_bound',
        'context_update_bound','diff_open_close_bound','accepted_rejected_bound',
        'stdin_transport_closed','session_persistence_attested','reconnect_state_reconciled',
        'unknown_remote_effect_absent','duplicate_notification_deduped'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | lifecycle_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_session_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S46-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['ACP', 'INITIALIZE', 'NEW_SESSION', 'LOAD_SESSION', 'PROMPT', 'CANCEL', 'NOTIFICATION', 'TOOL_CALL', 'PERMISSION', 'CONTEXT_UPDATE', 'DIFF', 'STDIO', 'RECONNECT', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
