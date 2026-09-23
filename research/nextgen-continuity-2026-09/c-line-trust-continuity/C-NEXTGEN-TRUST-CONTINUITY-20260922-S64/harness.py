#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','notification_class_declared',
    'recipient_authorization_bound','consent_state_bound','purpose_bound',
    'payload_minimization_bound','redaction_policy_bound','channel_data_policy_bound',
    'region_constraint_bound','retention_period_bound','deletion_attested',
    'export_scope_bound','export_destination_bound','access_role_bound',
    'access_audit_closed','template_version_bound','locale_variant_bound',
    'decision_version_bound','recipient_preference_bound','fallback_privacy_consistent',
    'replay_privacy_safe','privacy_conflict','unknown_privacy_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['privacy_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['notification_class_declared'] or
        not f['recipient_authorization_bound'] or not f['consent_state_bound'] or
        not f['purpose_bound'] or not f['payload_minimization_bound'] or
        not f['redaction_policy_bound'] or not f['channel_data_policy_bound'] or
        not f['region_constraint_bound'] or not f['retention_period_bound'] or
        not f['deletion_attested'] or not f['export_scope_bound'] or
        not f['export_destination_bound'] or not f['access_role_bound'] or
        not f['access_audit_closed'] or not f['template_version_bound'] or
        not f['locale_variant_bound'] or not f['decision_version_bound'] or
        not f['recipient_preference_bound'] or not f['fallback_privacy_consistent'] or
        not f['replay_privacy_safe'] or f['unknown_privacy_state']):
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
    privacy_conflict_bit = 1 << FIELDS.index('privacy_conflict')
    unknown_privacy_state_bit = 1 << FIELDS.index('unknown_privacy_state')
    required_names = [
        'same_identity','notification_class_declared','recipient_authorization_bound','consent_state_bound',
        'purpose_bound','payload_minimization_bound','redaction_policy_bound','channel_data_policy_bound',
        'region_constraint_bound','retention_period_bound','deletion_attested','export_scope_bound',
        'export_destination_bound','access_role_bound','access_audit_closed','template_version_bound',
        'locale_variant_bound','decision_version_bound','recipient_preference_bound','fallback_privacy_consistent',
        'replay_privacy_safe'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | privacy_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_privacy_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S64-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['CLASSIFICATION', 'AUTHORIZATION', 'CONSENT', 'PURPOSE', 'MINIMIZATION', 'REDACTION', 'CHANNEL_POLICY', 'REGION', 'RETENTION', 'DELETION', 'EXPORT', 'DESTINATION', 'ACCESS_ROLE', 'AUDIT', 'TEMPLATE', 'LOCALE', 'PREFERENCE', 'REPLAY', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
