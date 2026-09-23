#!/usr/bin/env python3
import hashlib, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
FIELDS = [
    'same_identity','identity_conflict','hook_declared','event_scope_bound',
    'hook_order_closed','stdout_schema_valid','exit_semantics_known','timeout_bound',
    'continue_semantics_known','decision_semantics_known','fingerprint_trust_bound',
    'subagent_declared','subagent_tools_bound','mcp_scope_bound','max_turns_bound',
    'timeout_mins_bound','history_isolated','tool_isolation_bound','recursion_guard_bound',
    'policy_override_bound','model_override_bound','result_state_readback',
    'hook_conflict','unknown_loop_effect'
]

def stable_digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def classify(f):
    if f['identity_conflict'] or f['hook_conflict']:
        return 'REJECT'
    if (not f['same_identity'] or not f['hook_declared'] or not f['event_scope_bound'] or
        not f['hook_order_closed'] or not f['stdout_schema_valid'] or not f['exit_semantics_known'] or
        not f['timeout_bound'] or not f['continue_semantics_known'] or not f['decision_semantics_known'] or
        not f['fingerprint_trust_bound'] or not f['subagent_declared'] or
        not f['subagent_tools_bound'] or not f['mcp_scope_bound'] or not f['max_turns_bound'] or
        not f['timeout_mins_bound'] or not f['history_isolated'] or not f['tool_isolation_bound'] or
        not f['recursion_guard_bound'] or not f['policy_override_bound'] or
        not f['model_override_bound'] or not f['result_state_readback'] or f['unknown_loop_effect']):
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
    hook_conflict_bit = 1 << FIELDS.index('hook_conflict')
    unknown_loop_effect_bit = 1 << FIELDS.index('unknown_loop_effect')
    required_names = [
        'same_identity','hook_declared','event_scope_bound','hook_order_closed','stdout_schema_valid',
        'exit_semantics_known','timeout_bound','continue_semantics_known','decision_semantics_known',
        'fingerprint_trust_bound','subagent_declared','subagent_tools_bound','mcp_scope_bound',
        'max_turns_bound','timeout_mins_bound','history_isolated','tool_isolation_bound',
        'recursion_guard_bound','policy_override_bound','model_override_bound','result_state_readback'
    ]
    required_mask = sum(1 << FIELDS.index(name) for name in required_names)
    reject_mask = identity_conflict_bit | hook_conflict_bit
    sweep_counts = {'RECOVERED': 0, 'UNKNOWN': 0, 'REJECT': 0}
    minimizers = []
    found = set()
    for mask in range(combinations):
        if mask & reject_mask:
            status = 'REJECT'
        elif (mask & required_mask) != required_mask or mask & unknown_loop_effect_bit:
            status = 'UNKNOWN'
        else:
            status = 'RECOVERED'
        sweep_counts[status] += 1
        if status not in found:
            minimizers.append({'target': status, 'mask': mask, 'bits': [i for i in range(len(FIELDS)) if mask & (1 << i)]})
            found.add(status)
    result = {
        'schema_version': 'S52-results-1', 'synthetic_only': True, 'production_verified': False,
        'claims_status': 'inferred', 'sources': [], 'case_count': len(rows), 'results': rows,
        'status_distribution': counts, 'all_cases_match': all(r['match'] for r in rows),
        'coverage': ['HOOK', 'SESSION_START', 'BEFORE_AGENT', 'AFTER_AGENT', 'BEFORE_TOOL', 'AFTER_TOOL', 'PRECOMPRESS', 'STDOUT_JSON', 'EXIT_CODE', 'TIMEOUT', 'CONTINUE', 'DECISION', 'FINGERPRINT', 'TRUST', 'SUBAGENT', 'MCP', 'MAX_TURNS', 'HISTORY', 'ISOLATION', 'RECURSION', 'POLICY_OVERRIDE', 'MODEL_OVERRIDE', 'NO_EVENT', 'UNKNOWN'],
        'property_sweep': {'dimensions': len(FIELDS), 'combinations': combinations, 'fields': FIELDS, 'counts': sweep_counts, 'single_gate_minimizer': minimizers}
    }
    result['digest'] = stable_digest(rows)
    (ROOT / 'outputs' / 'results.json').write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    return 0 if result['all_cases_match'] and combinations == (1 << len(FIELDS)) else 1

if __name__ == '__main__':
    raise SystemExit(main())
