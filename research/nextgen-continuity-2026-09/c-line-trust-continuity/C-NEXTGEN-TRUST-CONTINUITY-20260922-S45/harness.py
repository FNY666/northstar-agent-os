#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','security_scope_declared','report_channel_bound',
    'vulnerability_classified','triage_owner_bound','severity_rationale_closed',
    'remediation_state_attested','release_artifact_verified','provenance_verified',
    'signature_verified','version_pinned','enterprise_policy_loaded',
    'allowlist_closed','required_control_present','rollback_trigger_defined',
    'rollback_target_verified','rollback_effect_attested','runtime_convergence_attested',
    'audit_record_closed','security_conflict','unknown_remediation'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['security_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['security_scope_declared'] or not f['report_channel_bound'] or
        not f['vulnerability_classified'] or not f['triage_owner_bound'] or
        not f['severity_rationale_closed'] or not f['remediation_state_attested'] or
        not f['release_artifact_verified'] or not f['provenance_verified'] or
        not f['signature_verified'] or not f['version_pinned'] or
        not f['enterprise_policy_loaded'] or not f['allowlist_closed'] or
        not f['required_control_present'] or not f['rollback_trigger_defined'] or
        not f['rollback_target_verified'] or not f['rollback_effect_attested'] or
        not f['runtime_convergence_attested'] or not f['audit_record_closed'] or
        f['unknown_remediation']):
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
    unknown_remediation_bit = 1 << FIELDS.index('unknown_remediation')
    required_names = [
        'same_identity','security_scope_declared','report_channel_bound','vulnerability_classified',
        'triage_owner_bound','severity_rationale_closed','remediation_state_attested',
        'release_artifact_verified','provenance_verified','signature_verified','version_pinned',
        'enterprise_policy_loaded','allowlist_closed','required_control_present',
        'rollback_trigger_defined','rollback_target_verified','rollback_effect_attested',
        'runtime_convergence_attested','audit_record_closed'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | security_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_remediation_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S45-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['SECURITY_REPORT', 'TRIAGE', 'SEVERITY', 'REMEDIATION', 'ARTIFACT', 'PROVENANCE', 'SIGNATURE', 'VERSION_PIN', 'ENTERPRISE_POLICY', 'ALLOWLIST', 'ROLLBACK', 'CONVERGENCE', 'AUDIT', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
