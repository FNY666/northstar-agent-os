#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','decision_version_bound',
    'supersession_chain_closed','reopen_reason_bound','revoke_state_bound',
    'effective_window_bound','recipient_state_bound','ack_transition_bound',
    'read_state_semantics_known','unack_state_closed','delivery_evidence_retained',
    'retention_policy_bound','export_manifest_bound','audit_digest_bound',
    'cross_channel_consistency','recipient_reconciliation_closed','late_ack_handled',
    'stale_decision_rejected','reissue_id_bound','dedup_reissue_bound',
    'final_state_readback','notification_conflict','unknown_propagation_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['notification_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['decision_version_bound'] or not f['supersession_chain_closed'] or
        not f['reopen_reason_bound'] or not f['revoke_state_bound'] or not f['effective_window_bound'] or
        not f['recipient_state_bound'] or not f['ack_transition_bound'] or not f['read_state_semantics_known'] or
        not f['unack_state_closed'] or not f['delivery_evidence_retained'] or not f['retention_policy_bound'] or
        not f['export_manifest_bound'] or not f['audit_digest_bound'] or not f['cross_channel_consistency'] or
        not f['recipient_reconciliation_closed'] or not f['late_ack_handled'] or not f['stale_decision_rejected'] or
        not f['reissue_id_bound'] or not f['dedup_reissue_bound'] or not f['final_state_readback'] or
        f['unknown_propagation_state']):
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
    notification_conflict_bit = 1 << FIELDS.index('notification_conflict')
    unknown_propagation_state_bit = 1 << FIELDS.index('unknown_propagation_state')
    required_names = [
        'same_identity','decision_version_bound','supersession_chain_closed','reopen_reason_bound',
        'revoke_state_bound','effective_window_bound','recipient_state_bound','ack_transition_bound',
        'read_state_semantics_known','unack_state_closed','delivery_evidence_retained','retention_policy_bound',
        'export_manifest_bound','audit_digest_bound','cross_channel_consistency','recipient_reconciliation_closed',
        'late_ack_handled','stale_decision_rejected','reissue_id_bound','dedup_reissue_bound','final_state_readback'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | notification_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_propagation_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S63-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['DECISION_VERSION', 'SUPERSESSION', 'REOPEN', 'REVOKE', 'EFFECTIVE_WINDOW', 'RECIPIENT_STATE', 'ACK_TRANSITION', 'READ_STATE', 'UNACK', 'RETENTION', 'EXPORT', 'AUDIT', 'RECONCILIATION', 'LATE_ACK', 'STALE_DECISION', 'REISSUE', 'DEDUP', 'READBACK', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
