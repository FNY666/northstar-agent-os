#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','agent_card_bound','auth_scheme_declared',
    'auth_credential_bound','proxy_scope_known','streaming_capability_known',
    'task_id_bound','context_id_bound','message_request_bound','task_status_bound',
    'artifact_update_bound','status_update_order_closed','session_state_persisted',
    'cross_invocation_state_bound','abort_signal_bound','cancel_state_observed',
    'error_classified','retry_policy_known','remote_effect_readback',
    'a2a_version_compatible','auth_conflict','unknown_remote_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['auth_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['agent_card_bound'] or not f['auth_scheme_declared'] or
        not f['auth_credential_bound'] or not f['proxy_scope_known'] or
        not f['streaming_capability_known'] or not f['task_id_bound'] or
        not f['context_id_bound'] or not f['message_request_bound'] or
        not f['task_status_bound'] or not f['artifact_update_bound'] or
        not f['status_update_order_closed'] or not f['session_state_persisted'] or
        not f['cross_invocation_state_bound'] or not f['abort_signal_bound'] or
        not f['cancel_state_observed'] or not f['error_classified'] or
        not f['retry_policy_known'] or not f['remote_effect_readback'] or
        not f['a2a_version_compatible'] or f['unknown_remote_state']):
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
    auth_conflict_bit = 1 << FIELDS.index('auth_conflict')
    unknown_remote_state_bit = 1 << FIELDS.index('unknown_remote_state')
    required_names = [
        'same_identity','agent_card_bound','auth_scheme_declared','auth_credential_bound',
        'proxy_scope_known','streaming_capability_known','task_id_bound','context_id_bound',
        'message_request_bound','task_status_bound','artifact_update_bound',
        'status_update_order_closed','session_state_persisted','cross_invocation_state_bound',
        'abort_signal_bound','cancel_state_observed','error_classified','retry_policy_known',
        'remote_effect_readback','a2a_version_compatible'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | auth_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_remote_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S53-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['A2A', 'AGENT_CARD', 'AUTH', 'PROXY', 'STREAMING', 'TASK', 'CONTEXT', 'MESSAGE', 'STATUS_UPDATE', 'ARTIFACT_UPDATE', 'SESSION_STATE', 'INVOCATION', 'ABORT', 'ERROR', 'RETRY', 'VERSION', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
