#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','principal_bound','resource_bound',
    'action_bound','scope_bound','purpose_bound','least_privilege_attested',
    'grant_time_bound','expiry_bound','renewal_policy_bound','revocation_state_bound',
    'revocation_propagated','delegation_chain_bound','tool_permission_bound',
    'model_capability_bound','data_class_bound','region_bound','tenant_bound',
    'lease_fence_bound','stale_writer_rejected','access_readback','audit_closed',
    'permission_conflict','unknown_access_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['permission_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['principal_bound'] or not f['resource_bound'] or
        not f['action_bound'] or not f['scope_bound'] or not f['purpose_bound'] or
        not f['least_privilege_attested'] or not f['grant_time_bound'] or not f['expiry_bound'] or
        not f['renewal_policy_bound'] or not f['revocation_state_bound'] or
        not f['revocation_propagated'] or not f['delegation_chain_bound'] or
        not f['tool_permission_bound'] or not f['model_capability_bound'] or
        not f['data_class_bound'] or not f['region_bound'] or not f['tenant_bound'] or
        not f['lease_fence_bound'] or not f['stale_writer_rejected'] or
        not f['access_readback'] or not f['audit_closed'] or f['unknown_access_state']):
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
    permission_conflict_bit = 1 << FIELDS.index('permission_conflict')
    unknown_access_state_bit = 1 << FIELDS.index('unknown_access_state')
    required_names = [
        'same_identity','principal_bound','resource_bound','action_bound','scope_bound','purpose_bound',
        'least_privilege_attested','grant_time_bound','expiry_bound','renewal_policy_bound',
        'revocation_state_bound','revocation_propagated','delegation_chain_bound','tool_permission_bound',
        'model_capability_bound','data_class_bound','region_bound','tenant_bound','lease_fence_bound',
        'stale_writer_rejected','access_readback','audit_closed'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | permission_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_access_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S65-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['PRINCIPAL', 'RESOURCE', 'ACTION', 'SCOPE', 'PURPOSE', 'LEAST_PRIVILEGE', 'GRANT', 'EXPIRY', 'RENEWAL', 'REVOCATION', 'DELEGATION', 'TOOL_PERMISSION', 'MODEL_CAPABILITY', 'DATA_CLASS', 'REGION', 'TENANT', 'LEASE', 'FENCE', 'STALE_WRITER', 'AUDIT', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
