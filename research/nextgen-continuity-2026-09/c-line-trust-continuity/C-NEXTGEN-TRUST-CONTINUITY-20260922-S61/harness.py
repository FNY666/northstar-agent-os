#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','decision_id_bound','reviewer_identity_bound',
    'reviewer_role_bound','separation_of_duties_closed','approval_scope_bound',
    'approval_evidence_bound','override_reason_bound','override_authorized',
    'dissent_recorded','appeal_path_bound','appeal_owner_bound','reopen_condition_bound',
    'decision_version_monotonic','prior_decision_digest_bound','effective_time_bound',
    'expiry_review_bound','audit_sequence_closed','notification_bound','stakeholder_ack_bound',
    'final_decision_readback','review_conflict','unknown_review_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['review_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['decision_id_bound'] or not f['reviewer_identity_bound'] or
        not f['reviewer_role_bound'] or not f['separation_of_duties_closed'] or
        not f['approval_scope_bound'] or not f['approval_evidence_bound'] or
        not f['override_reason_bound'] or not f['override_authorized'] or
        not f['dissent_recorded'] or not f['appeal_path_bound'] or not f['appeal_owner_bound'] or
        not f['reopen_condition_bound'] or not f['decision_version_monotonic'] or
        not f['prior_decision_digest_bound'] or not f['effective_time_bound'] or
        not f['expiry_review_bound'] or not f['audit_sequence_closed'] or
        not f['notification_bound'] or not f['stakeholder_ack_bound'] or
        not f['final_decision_readback'] or f['unknown_review_state']):
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
    review_conflict_bit = 1 << FIELDS.index('review_conflict')
    unknown_review_state_bit = 1 << FIELDS.index('unknown_review_state')
    required_names = [
        'same_identity','decision_id_bound','reviewer_identity_bound','reviewer_role_bound',
        'separation_of_duties_closed','approval_scope_bound','approval_evidence_bound',
        'override_reason_bound','override_authorized','dissent_recorded','appeal_path_bound',
        'appeal_owner_bound','reopen_condition_bound','decision_version_monotonic',
        'prior_decision_digest_bound','effective_time_bound','expiry_review_bound',
        'audit_sequence_closed','notification_bound','stakeholder_ack_bound','final_decision_readback'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | review_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_review_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S61-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['DECISION', 'REVIEWER', 'ROLE', 'SEPARATION_OF_DUTIES', 'APPROVAL', 'OVERRIDE', 'DISSENT', 'APPEAL', 'REOPEN', 'VERSION', 'EFFECTIVE_TIME', 'EXPIRY', 'AUDIT', 'NOTIFICATION', 'ACK', 'READBACK', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
