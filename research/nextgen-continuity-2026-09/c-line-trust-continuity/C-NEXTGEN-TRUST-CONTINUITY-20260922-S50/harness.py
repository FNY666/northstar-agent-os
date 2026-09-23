#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','auth_method_declared','credential_source_bound',
    'token_scope_valid','token_fresh','quota_scope_known','quota_remaining_known',
    'billing_mode_known','billing_identity_bound','privacy_policy_bound','telemetry_policy_bound',
    'model_requested_bound','model_selected_readback','fallback_policy_known',
    'provider_identity_bound','routing_precedence_known','rate_limit_state_known',
    'retry_charge_semantics_known','region_constraint_known','usage_record_closed',
    'auth_route_conflict','unknown_provider_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['auth_route_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['auth_method_declared'] or not f['credential_source_bound'] or
        not f['token_scope_valid'] or not f['token_fresh'] or not f['quota_scope_known'] or
        not f['quota_remaining_known'] or not f['billing_mode_known'] or not f['billing_identity_bound'] or
        not f['privacy_policy_bound'] or not f['telemetry_policy_bound'] or not f['model_requested_bound'] or
        not f['model_selected_readback'] or not f['fallback_policy_known'] or not f['provider_identity_bound'] or
        not f['routing_precedence_known'] or not f['rate_limit_state_known'] or
        not f['retry_charge_semantics_known'] or not f['region_constraint_known'] or
        not f['usage_record_closed'] or f['unknown_provider_state']):
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
    auth_route_conflict_bit = 1 << FIELDS.index('auth_route_conflict')
    unknown_provider_state_bit = 1 << FIELDS.index('unknown_provider_state')
    required_names = [
        'same_identity','auth_method_declared','credential_source_bound','token_scope_valid','token_fresh',
        'quota_scope_known','quota_remaining_known','billing_mode_known','billing_identity_bound',
        'privacy_policy_bound','telemetry_policy_bound','model_requested_bound','model_selected_readback',
        'fallback_policy_known','provider_identity_bound','routing_precedence_known','rate_limit_state_known',
        'retry_charge_semantics_known','region_constraint_known','usage_record_closed'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | auth_route_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_provider_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S50-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['AUTH_METHOD', 'CREDENTIAL', 'SCOPE', 'FRESHNESS', 'QUOTA', 'BILLING', 'PRIVACY', 'TELEMETRY', 'MODEL', 'FALLBACK', 'ROUTING_PRECEDENCE', 'RATE_LIMIT', 'RETRY', 'USAGE', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
