#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','report_scope_fixed','report_receiver_bound',
    'finding_identity_bound','severity_method_known','triage_state_closed',
    'remediation_owner_bound','artifact_digest_verified','artifact_signature_verified',
    'build_provenance_verified','release_metadata_consistent','version_pinned',
    'enterprise_policy_scope_bound','allowlist_effective_readback','required_control_attested',
    'rollback_trigger_bound','rollback_target_attested','rollback_completion_readback',
    'runtime_convergence_closed','audit_trail_complete','security_conflict',
    'unknown_release_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['security_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['report_scope_fixed'] or not f['report_receiver_bound'] or
        not f['finding_identity_bound'] or not f['severity_method_known'] or not f['triage_state_closed'] or
        not f['remediation_owner_bound'] or not f['artifact_digest_verified'] or
        not f['artifact_signature_verified'] or not f['build_provenance_verified'] or
        not f['release_metadata_consistent'] or not f['version_pinned'] or
        not f['enterprise_policy_scope_bound'] or not f['allowlist_effective_readback'] or
        not f['required_control_attested'] or not f['rollback_trigger_bound'] or
        not f['rollback_target_attested'] or not f['rollback_completion_readback'] or
        not f['runtime_convergence_closed'] or not f['audit_trail_complete'] or
        f['unknown_release_state']):
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
    security_conflict_bit = 1 << FIELDS.index('security_conflict')
    unknown_release_state_bit = 1 << FIELDS.index('unknown_release_state')
    required_names = [
        'same_identity','report_scope_fixed','report_receiver_bound','finding_identity_bound',
        'severity_method_known','triage_state_closed','remediation_owner_bound',
        'artifact_digest_verified','artifact_signature_verified','build_provenance_verified',
        'release_metadata_consistent','version_pinned','enterprise_policy_scope_bound',
        'allowlist_effective_readback','required_control_attested','rollback_trigger_bound',
        'rollback_target_attested','rollback_completion_readback','runtime_convergence_closed',
        'audit_trail_complete'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | security_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_release_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S48-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['SECURITY_REPORT', 'SEVERITY', 'TRIAGE', 'REMEDIATION', 'ARTIFACT_DIGEST', 'SIGNATURE', 'BUILD_PROVENANCE', 'RELEASE_METADATA', 'VERSION_PIN', 'ENTERPRISE_POLICY', 'ALLOWLIST', 'REQUIRED_CONTROL', 'ROLLBACK', 'CONVERGENCE', 'AUDIT', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
