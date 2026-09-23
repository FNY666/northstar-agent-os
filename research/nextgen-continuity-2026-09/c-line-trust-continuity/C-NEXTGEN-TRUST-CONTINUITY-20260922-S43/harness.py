#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','tool_declared','tool_scope_allowed',
    'policy_decision_attested','approval_required_known','approval_obtained',
    'sandbox_boundary_closed','cwd_boundary_closed','path_allowlist_closed',
    'command_arguments_bound','input_canonical','output_captured',
    'side_effect_attested','postcondition_readback','timeout_semantics_known',
    'failure_state_known','retry_policy_known','user_visible_result_bound',
    'tool_chain_complete','permission_conflict','unknown_side_effect'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['permission_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['tool_declared'] or not f['tool_scope_allowed'] or
        not f['policy_decision_attested'] or not f['approval_required_known'] or
        not f['approval_obtained'] or not f['sandbox_boundary_closed'] or
        not f['cwd_boundary_closed'] or not f['path_allowlist_closed'] or
        not f['command_arguments_bound'] or not f['input_canonical'] or
        not f['output_captured'] or not f['side_effect_attested'] or
        not f['postcondition_readback'] or not f['timeout_semantics_known'] or
        not f['failure_state_known'] or not f['retry_policy_known'] or
        not f['user_visible_result_bound'] or not f['tool_chain_complete'] or
        f['unknown_side_effect']):
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
    unknown_side_effect_bit = 1 << FIELDS.index('unknown_side_effect')
    required_names = [
        'same_identity','tool_declared','tool_scope_allowed','policy_decision_attested',
        'approval_required_known','approval_obtained','sandbox_boundary_closed',
        'cwd_boundary_closed','path_allowlist_closed','command_arguments_bound',
        'input_canonical','output_captured','side_effect_attested','postcondition_readback',
        'timeout_semantics_known','failure_state_known','retry_policy_known',
        'user_visible_result_bound','tool_chain_complete'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | permission_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_side_effect_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S43-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['TOOL_DECLARATION', 'POLICY', 'APPROVAL', 'SHELL', 'FILESYSTEM', 'ASK_USER', 'SKILL', 'SANDBOX', 'CWD', 'ALLOWLIST', 'POSTCONDITION', 'TIMEOUT', 'RETRY', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
