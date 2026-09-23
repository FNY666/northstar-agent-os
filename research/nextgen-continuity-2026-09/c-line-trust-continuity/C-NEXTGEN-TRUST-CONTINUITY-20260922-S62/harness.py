#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','notification_id_bound','decision_version_bound',
    'recipient_set_closed','channel_bound','payload_digest_bound','delivery_attempt_bound',
    'delivery_receipt_bound','retry_state_bound','dedup_key_bound','ack_semantics_known',
    'ack_bound','ack_timestamp_bound','deadline_bound','escalation_policy_bound',
    'escalation_owner_bound','channel_fallback_bound','coverage_reconciled',
    'notification_order_closed','final_decision_readback','audit_record_closed',
    'notification_conflict','unknown_delivery_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['notification_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['notification_id_bound'] or not f['decision_version_bound'] or
        not f['recipient_set_closed'] or not f['channel_bound'] or not f['payload_digest_bound'] or
        not f['delivery_attempt_bound'] or not f['delivery_receipt_bound'] or not f['retry_state_bound'] or
        not f['dedup_key_bound'] or not f['ack_semantics_known'] or not f['ack_bound'] or
        not f['ack_timestamp_bound'] or not f['deadline_bound'] or not f['escalation_policy_bound'] or
        not f['escalation_owner_bound'] or not f['channel_fallback_bound'] or not f['coverage_reconciled'] or
        not f['notification_order_closed'] or not f['final_decision_readback'] or not f['audit_record_closed'] or
        f['unknown_delivery_state']):
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
    unknown_delivery_state_bit = 1 << FIELDS.index('unknown_delivery_state')
    required_names = [
        'same_identity','notification_id_bound','decision_version_bound','recipient_set_closed','channel_bound',
        'payload_digest_bound','delivery_attempt_bound','delivery_receipt_bound','retry_state_bound',
        'dedup_key_bound','ack_semantics_known','ack_bound','ack_timestamp_bound','deadline_bound',
        'escalation_policy_bound','escalation_owner_bound','channel_fallback_bound','coverage_reconciled',
        'notification_order_closed','final_decision_readback','audit_record_closed'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | notification_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_delivery_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S62-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['NOTIFICATION', 'RECIPIENT_SET', 'CHANNEL', 'PAYLOAD_DIGEST', 'ATTEMPT', 'RECEIPT', 'RETRY', 'DEDUP', 'ACK', 'DEADLINE', 'ESCALATION', 'FALLBACK', 'COVERAGE', 'ORDER', 'READBACK', 'AUDIT', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
