#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','test_spec_declared','behavior_assertion_bound',
    'expected_output_bound','tool_behavior_bound','fixture_isolated','environment_declared',
    'sandbox_matrix_complete','docker_path_checked','podman_path_checked','no_sandbox_path_checked',
    'blocking_errors_separated','warnings_separated','repeat_runs_complete','repeat_results_stable',
    'integration_boundary_closed','resource_baseline_recorded','failure_injection_attested',
    'external_effect_not_claimed','test_conflict','unknown_test_state'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['test_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['test_spec_declared'] or not f['behavior_assertion_bound'] or
        not f['expected_output_bound'] or not f['tool_behavior_bound'] or not f['fixture_isolated'] or
        not f['environment_declared'] or not f['sandbox_matrix_complete'] or not f['docker_path_checked'] or
        not f['podman_path_checked'] or not f['no_sandbox_path_checked'] or
        not f['blocking_errors_separated'] or not f['warnings_separated'] or
        not f['repeat_runs_complete'] or not f['repeat_results_stable'] or
        not f['integration_boundary_closed'] or not f['resource_baseline_recorded'] or
        not f['failure_injection_attested'] or not f['external_effect_not_claimed'] or
        f['unknown_test_state']):
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
    test_conflict_bit = 1 << FIELDS.index('test_conflict')
    unknown_test_state_bit = 1 << FIELDS.index('unknown_test_state')
    required_names = [
        'same_identity','test_spec_declared','behavior_assertion_bound','expected_output_bound',
        'tool_behavior_bound','fixture_isolated','environment_declared','sandbox_matrix_complete',
        'docker_path_checked','podman_path_checked','no_sandbox_path_checked',
        'blocking_errors_separated','warnings_separated','repeat_runs_complete',
        'repeat_results_stable','integration_boundary_closed','resource_baseline_recorded',
        'failure_injection_attested','external_effect_not_claimed'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | test_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_test_state_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S47-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['BEHAVIORAL_EVAL', 'INTEGRATION_TEST', 'BLOCKING_ERROR', 'WARNING', 'SANDBOX', 'FIXTURE', 'REPEAT_RUN', 'FAILURE_INJECTION', 'RESOURCE_BASELINE', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
