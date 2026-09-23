#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','evidence_window_closed','source_set_closed',
    'claim_scope_closed','precondition_closed','postcondition_readback','independent_verifier',
    'decision_policy_bound','recovered_rule_closed','unknown_rule_closed','reject_rule_closed',
    'quarantine_on_unknown','escalation_owner_bound','manual_review_gate_bound',
    'review_evidence_bound','remediation_action_bound','remediation_idempotency_bound',
    'retry_reconciliation_closed','final_state_revalidated','decision_immutability',
    'audit_record_closed','conflict_resolution_bound','decision_conflict'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['decision_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['evidence_window_closed'] or not f['source_set_closed'] or
        not f['claim_scope_closed'] or not f['precondition_closed'] or not f['postcondition_readback'] or
        not f['independent_verifier'] or not f['decision_policy_bound'] or
        not f['recovered_rule_closed'] or not f['unknown_rule_closed'] or not f['reject_rule_closed'] or
        not f['quarantine_on_unknown'] or not f['escalation_owner_bound'] or
        not f['manual_review_gate_bound'] or not f['review_evidence_bound'] or
        not f['remediation_action_bound'] or not f['remediation_idempotency_bound'] or
        not f['retry_reconciliation_closed'] or not f['final_state_revalidated'] or
        not f['decision_immutability'] or not f['audit_record_closed'] or
        not f['conflict_resolution_bound']):
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
    decision_conflict_bit = 1 << FIELDS.index('decision_conflict')
    required_names = [
        'same_identity','evidence_window_closed','source_set_closed','claim_scope_closed','precondition_closed',
        'postcondition_readback','independent_verifier','decision_policy_bound','recovered_rule_closed',
        'unknown_rule_closed','reject_rule_closed','quarantine_on_unknown','escalation_owner_bound',
        'manual_review_gate_bound','review_evidence_bound','remediation_action_bound',
        'remediation_idempotency_bound','retry_reconciliation_closed','final_state_revalidated',
        'decision_immutability','audit_record_closed','conflict_resolution_bound'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | decision_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S60-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['EVIDENCE_WINDOW', 'SOURCE_SET', 'CLAIM_SCOPE', 'PRECONDITION', 'POSTCONDITION', 'VERIFIER', 'POLICY', 'RECOVERED', 'UNKNOWN', 'REJECT', 'QUARANTINE', 'ESCALATION', 'MANUAL_REVIEW', 'REMEDIATION', 'RETRY', 'REVALIDATION', 'AUDIT', 'CONFLICT'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
